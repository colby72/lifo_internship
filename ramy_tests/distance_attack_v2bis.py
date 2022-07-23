# @author: Ramy CHEMAK
# @university: INSA Centre Val de Loire et Université d'Orléans
# @laboratory: Laboratoire d'Informatique Fondamentale d'Orléans (LIFO-EA 4022)


import pprint

from gdascore.gdaAttack import gdaAttack
from gdascore.gdaTools import setupGdaAttackParameters
from gdascore.gdaScore import gdaScores
from gdascore.gdaTools import setupGdaAttackParameters, comma_ize, finishGdaAttack

pp = pprint.PrettyPrinter(indent=4)

# @author: Ramy Chemak

# ---------- Distance-based attack ----------

# The attack assumes we already have some intelligence on some individuals
# in the raw database.
# These could have been acquired from an open source platform or by other means.

# The principle of the algorithm is to measure distance between these individual
# raw information we have and the de-identified records in the dataset.
# We look for the closest record within the de-identified DB to try to identify
# a particular individual.

# The distance is calculated based on values of common attributes between raw
# (the some we have) and and de-identified databases.
# Distance between two records is an aggregation of distances between common attributes.
# Distance between two values of the same attribute depends on variable type.
# For example, we can consider that distance between two floats is their difference.
# Whereas distance for binary attributes (such as 'Gender') is either 0 or 1.

# This implementation is a prototype.
# Some aspects of the attack can be improved, and others aren't yet implemented.


def distance_attack(params, verbose):
    # Check on parameters
    print("########## Parameters passed ##########")
    pp.pprint(params)
    # Attack setup
    attack = gdaAttack(params)
    attack.unsetVerbose()
    print("\nInfo >>> Attack Class created\n")
    # Exploring table schema
    table = attack.getAttackTableName()
    print(f"\nInfo >>> Working on table : {table} ...")
    rawColNames = attack.getColNames(dbType="rawDb")
    anonColNames = attack.getColNames(dbType="anonDb")
    uidCol = attack.getUidColName()
    raw_schema = dict()
    for col in rawColNames:
        publicValues = attack.getPublicColValues(col, table)
        if publicValues:
            values = []
            for t in publicValues:
                values.append(t[0])
            #print("debug1 > values: ", values)
            raw_schema[col] = values
    # Preparing the attack
    print("\nInfo >>> Preparing the attack columns ...\n")
    cols = [] # columns to be attacked
    queries = [] # list of queries for knowledge acquiring
    for col in anonColNames:
        if col==uidCol:
            continue
        publicValues = attack.getPublicColValues(col, table)
        if publicValues:
            values = []
            for t in publicValues:
                values.append(t[0])
        if len(values) < 2:
            continue
        cols.append(col)
    print("\nInfo >>> Attack columns selected ...")
    print(f"... {cols}\n")
    # Get a list all anonymized users' data
    print("\nInfo >>> Retrieving users' useful data ...")
    raw_data = {} # look like {'uid': [val1, val2, ..., valn], ...}
    anon_data = {} # look like {'uid': [val1, val2, ..., valn], ...}
    cols2 = cols[:]
    cols2.insert(0, uidCol)
    query = {}
    sql = sqlQueryGen(table, cols2, None, None)
    print(f"... SQL query : {sql}")
    query['sql'] = sql
    # fill in raw_data
    print("... users' raw data")
    query['db'] = "rawDb"
    attack.askExplore(query)
    while True:
        reply = attack.getExplore()
        if reply["stillToCome"]==0:
            break
    if "answer" in reply.keys():
        for a in reply['answer']:
            raw_data[a[0]] = a[1:]
    # fill in anon_data
    print("... users' anonymized data\n")
    query['db'] = "anonDb"
    attack.askExplore(query)
    while True:
        reply = attack.getExplore()
        if reply["stillToCome"]==0:
            break
    if "answer" in reply.keys():
        for a in reply['answer']:
            anon_data[a[0]] = a[1:]
    print("Info >>> Users data retrieved !")
    if len(anon_data.keys())==0:
        print("\nError >>> No anonymized data to work on :(")
        return None
    i = 0
    for it in raw_data.items():
        i += 1
        if i>=2:
            break
    # Determine practically attackable columns
    att = [True] * len(cols) # list of whether the column is to consider or not
    uid_att = True
    i = 0
    for it in anon_data.items():
        samp = (it[0], list(it[1]))
        i += 1
        if i >= 1:
            break
    if samp[0]==None:
        uid_att = False
    for i in range(len(samp[1])):
        if samp[1][i] == None:
            att[i] = False
    att = (uid_att, att)
    # De-identification phase
    print("\nInfo >>> De-identifying users ...\n")
    matches = dict() # record of identified users ({"fake_id": "real_id"})
    repulses = dict() # record of identified users ({"fake_id": "real_id"})
    for anon_id in anon_data.keys():
        first = True
        for raw_id in raw_data.keys():
            d = compute_global_distance(raw_data[raw_id], anon_data[anon_id], att)
            if d == None:
                continue
            if first:
                matches[anon_id] = raw_id
                repulses[anon_id] = raw_id
                min = d
                max = d
                first = False
            elif d < min:
                matches[anon_id] = raw_id
                min = d
            elif d > max:
                repulses[anon_id] = raw_id
                max = d
    print("... de-identification finished")
    if not (matches.keys() or repulses.keys()):
        print("\nError >>> No user was de-identified\n")
        return None
    print(f"... {len(matches.keys())} matches found :)")
    # Launching the attack
    print("\nInfo >>> Launching the attack ...\n")
    guess_all = [] # list of all guesses to make as claim=True
    guess_all_false = [] # list of all guesses to make as claim=False
    for m in matches.items():
        sg = [] # one single guess
        fid = m[0] # anonymized uid
        rid = m[1] # real uid
        for i in range(len(cols)):
            guessed_val = raw_data[rid][i]
            if guessed_val == None:
                continue
            sg.append({'col': cols[i], 'val': guessed_val})
        guess_all.append(sg)
    for m in repulses.items():
        fid = m[0] # anonymized uid
        rid = m[1] # real uid
        sg = [{'col': uidCol, 'val': fid}]
        for i in range(len(cols)):
            guessed_val = raw_data[rid][i]
            if guessed_val == None:
                continue
            sg.append({'col': cols[i], 'val': guessed_val})
        guess_all_false.append(sg)
    # Make some guesses
    print("\nInfo >>> Making claims ...\n")
    spec = {}
    nb_guess = 0
    for g in guess_all:
        spec['guess'] = g
        try:
            attack.askClaim(spec, claim=True)
        except:
            continue
    while True:
        claim = attack.getClaim()
        if claim["stillToCome"]==0:
            break
    # Compute and display score
    result = attack.getResults()
    gda_score = gdaScores(result)
    print("\nInfo >>> Score Class created\n")
    print("########## Attack score ##########")
    score = gda_score.getScores()
    if verbose:
        pp.pprint(score)
    # Abschliessung
    attack.cleanUp()
    final_result = finishGdaAttack(params, score)
    return None

def compute_distance(a, b, r=None):
    """
    Params:
    'r' refers to range of values when needed (int and float mainly)
    It's set to None when not needed
    Output:
    -1 for an error
    """
    # handling a temporary error
    if (None in [a, b]) or (type(a) != type(b)):
        return -1
    t = type(a)
    # regardless of type, values are the same and distance is null
    if a==b:
        return 0
    # we take into consideration the type to compute the distance
    elif (t==int) or (t==float):
        if (r == 0) or (r == None):
            return abs(a-b)
        return abs(a-b)/r
    elif (t==str) and (len(a)==1) and (len(b)==1):
        return abs(ord(a)-ord(b))
    # str not operational for the moment, lacking range calculations
    elif (1<0) and (t==str):
        (x, l) = (a.find(b), len(b))
        (y, l) = (b.find(a), len(a))
        m = max(x, y)
        if m==-1:
            return min(len(a), len(b))
        else:
            r = max(len(a), len(b)) - (m+l) # rest of letters by the end
            return m+r
    # siplified str calculus
    elif t==str:
        return 1
    elif (t==bool) or (t=="bool"):
        return 1
    else:
        return -1

def compute_global_distance(f, g, att, coef=None):
    """
    Params:
    'f' refers to the 1st field and 'g' to the second
    Output:
    None if an error occurs
    """
    # check whether both fields are of the same size
    l = len(f)
    if l!=len(g) or l==0:
        return None
    #print("debug > same length")
    if coef==None:
        coef = [1] * l
    gd = 0 # global distance
    for i in range(l):
        # check type compability for each column
        if att[1][i]:
            d = compute_distance(f[i], g[i])
            if d == -1:
                continue
            gd += d * coef[i]
    gd /= l
    return gd

def sqlQueryGen(table, cols, conditions, operator, opp=False):
    """
    Routine function to generate SQL queries
    If there is no conditions, parameter 'conditions' is set to None
    For a unique condition, 'conditions' is a string and 'operator' is set to None
    Else, 'conditions' is a table of strings and 'operator' is string
    """
    sql = "SELECT "
    sql += comma_ize(cols, lastComma=False)
    sql += " FROM " + table
    if conditions==None:
        return sql
    if operator==None:
        if opp:
            sql += " WHERE NOT(" + conditions + ")"
        else:
            sql += " WHERE " + conditions
    else:
        if opp:
            sql += " WHERE NOT(" + operator.join(conditions) + ")"
        else:
            sql += " WHERE " + operator.join(conditions)
    return sql

def format_guess(cols, vals):
    """
    Params:
    'cols' is a list of columns to attack
    'vals' is returned by result['answer'], ie. [(C1,C2...,Cn),(C1,C2...,Cn), ... (C1,C2...,Cn)]
    """
    guess = []
    item = {}
    for i in range(len(cols)):
        item['col'] = cols[i]
        item['val'] = vals[0][i]
        guess.append(item)
    return guess


config = {
    "basic": {
        "attackType": "Distance Attack v2 - singlingOut",
        "criteria": "singlingOut"
    },
    'anonTypes': [
        #["no_anon"],
        #["pseudonymization", "latest"],
        ["k_anonymization","naive","k_2"],
        #["k_anonymization","naive","k_5"],
        #["pseudonymization","kanon","k_2"],
        #["pseudonymization","kanon","k_5"]
    ],
    'tables': [
        #['banking','accounts'],
        #['banking','loans'],
        ['taxi','rides'],
    ]
}

# set general configuration parameters
paramsList = setupGdaAttackParameters(config)
params = paramsList[0]

# launch attack
verbose = False
distance_attack(params, verbose)
