# @author: Ramy CHEMAK
# @university: INSA Centre Val de Loire et Université d'Orléans
# @laboratory: Laboratoire d'Informatique Fondamentale d'Orléans (LIFO-EA 4022)


import pprint

from gdascore.gdaAttack import gdaAttack
from gdascore.gdaTools import setupGdaAttackParameters
from gdascore.gdaScore import gdaScores
from gdascore.gdaTools import setupGdaAttackParameters, comma_ize, finishGdaAttack

pp = pprint.PrettyPrinter(indent=4)

# The idea is, for each attribute, to get all records
# with a single or two counts for a given value,
# and this this for each value
# Then identify collisions between these records

def ramyAttack02(params, verbose):
    # Check on parameters
    print("########## Parameters passed ##########")
    pp.pprint(params)
    # Attack setup
    attack = gdaAttack(params)
    attack.unsetVerbose()
    print("\nInfo >>> Attack Class created")
    # Information gathering
    table = attack.getAttackTableName()
    rawColNames = attack.getColNames(dbType="rawDb")
    anonColNames = attack.getColNames(dbType="anonDb")
    print(f"\nInfo >>> Working on table : {table} ...")
    # Looking for interesting columns and values to fetch
    interestValues = [] # list (column, value) to investigate deeper
    uidCol = attack.getUidColName()
    for col in anonColNames:
        if (col != uidCol) and not ("id" in col):
            publicValues = attack.getPublicColValues(col, table)
            #print("debug1", publicValues)
            #print("debug2", col)
            for val in publicValues:
                if val[1]<=50:
                    interestValues.append((col, val[0]))
                    #print("debug3", val)
    if not interestValues:
        print("\nInfo >>> No interesting values found")
        return None
    else:
        print("\nInfo >>> Interesting values found\n")
        print("########## Interesting values ##########")
        pp.pprint(interestValues)
    # Numbering conditions
    print("\nInfo >>> Generating conditions ...")
    conditions = []
    condition = ""
    for val in interestValues:
        condition = f"{val[0]}={val[1]}"
        conditions.append(condition)
    # Define SQL queries
    print("\nInfo >>> Generating SQL queries ...")
    queries = []
    sql = ""
    for cond in conditions:
        sql = sqlQueryGen(table, anonColNames, cond)
        queries.append(sql)
    # executing attack
    query = {}
    query['db'] = "anonDb"
    print("\nInfo >>> Launching attack ...\n")
    for q in queries:
        query['sql'] = q
        attack.askAttack(query)
        #print("debug4", q)
    while True:
        reply = attack.getAttack()
        if reply["stillToCome"]==0:
            break
    #reply = attack.getAttack()
    if verbose:
        print("########## Attack reply ##########")
        pp.pprint(reply)
    # Make some guesses :3
    print("\nInfo >>> Making claims ...\n")
    if "answer" in reply.keys():
        for row in reply['answer']:
            spec = {}
            guess = []
            for i in range(len(anonColNames)):
                guess.append({'col':anonColNames[i],'val':row[i]})
            spec['guess'] = guess
            attack.askClaim(spec, claim=True)
        #claim = attack.getClaim()
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
    pp.pprint(score)
    # Abschliessung
    attack.cleanUp()
    final_result = finishGdaAttack(params, score)
    return None

def sqlQueryGen(table, cols, condition):
    """ Routine function to generate SQL queries """
    sql = "SELECT "
    sql += comma_ize(cols, lastComma=False)
    sql += " FROM " + table
    sql += " WHERE " + condition
    return sql


config = {
    "basic": {
        "attackType": "Ramy Test Attack",
        "criteria": "singlingOut"
    },
    'anonTypes': [
        ["no_anon"],
        ["pseudonymization", "latest"],
        ["diffix","latest"],
        ["diffix","v19_1_0"],
        ["k_anonymization","naive","k_2"],
        ["k_anonymization","naive","k_5"], # problem to investigate
        ["pseudonymization","colSuppression"],
        ["pseudonymization","kanon","k_2"],
        ["pseudonymization","kanon","k_5"]
    ],
    'tables': [
        ['taxi','rides'],
        #['census','persons'],
        #['scihub','downloads']
    ]
}

# set general configuration parameters
paramsList = setupGdaAttackParameters(config)
params = paramsList[0]

# launch attack
verbose = True
ramyAttack02(params, verbose)
