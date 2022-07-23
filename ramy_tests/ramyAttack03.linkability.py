# @author: Ramy CHEMAK
# @university: INSA Centre Val de Loire et Université d'Orléans
# @laboratory: Laboratoire d'Informatique Fondamentale d'Orléans (LIFO-EA 4022)


import pprint

from gdascore.gdaAttack import gdaAttack
from gdascore.gdaTools import setupGdaAttackParameters
from gdascore.gdaScore import gdaScores
from gdascore.gdaTools import setupGdaAttackParameters, comma_ize, finishGdaAttack

pp = pprint.PrettyPrinter(indent=4)

# Very similar to ramyAttack02
# But try to look at interesting values of columns across the DB
# especially for columns shared between different tables

def ramyAttack03(params, verbose):
    # Check on parameters
    print("########## Parameters passed ##########")
    pp.pprint(params)
    # Attack setup
    attack = gdaAttack(params)
    attack.unsetVerbose()
    print("\nInfo >>> Attack Class created\n")
    # Exploring DB schema
    tables = attack.getTableNames()
    print("debug1", tables)
    db_model = {} # dict of columns for each table
    for table in tables:
        print(f"\nInfo >>> Working on table : {table} ...")
        #print("debug2")
        #rawColNames = attack.getColNames(dbType="rawDb", tableName=table)
        #print("debug3")
        anonColNames = []
        try:
            anonColNames = attack.getColNames(dbType="anonDb", tableName=table)
            db_model[table] = anonColNames
        except:
            print(f"{table} doesn't exist .. Skip to next !")
            pass
        #print("debug4")
    # Looking for similar inter-table columns (in progress ...)
    print("\n########## Database model ##########\n")
    pp.pprint(db_model)
    # Back to target table ...
    table = attack.getAttackTableName()
    rawColNames = attack.getColNames(dbType="rawDb")
    anonColNames = attack.getColNames(dbType="anonDb")
    # Looking for interesting columns and values to fetch
    interestValues = [] # list of (column, value) tuples to investigate deeper
    uidCol = attack.getUidColName()
    for col in anonColNames:
        if (col != uidCol) and not ("id" in col):
            publicValues = attack.getPublicColValues(col, table)
            for val in publicValues:
                if val[1]<=50:
                    interestValues.append((col, val[0]))
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
    # Generate SQL queries regarding target table
    print("\nInfo >>> Generating SQL queries ...")
    queries = []
    sql = ""
    for cond in conditions:
        sql = sqlQueryGen(table, anonColNames, cond)
        queries.append(sql)
    # Looking at possible interesting inter-cross columns
    lucky_cols = [] # list of cols from interestValues
    interestCols = [] # list of (table, col) tuples for interesting inter-cross columns
    for i in interestValues:
        if not i[0] in lucky_cols:
            lucky_cols.append(i[0])
    for t in db_model.keys():
        if (t==table) or (not db_model[t]) or (db_model[t]==None):
            continue
        for c in db_model[t]:
            if c in lucky_cols:
                interestCols.append((t, c))
    # Generate SQL queries regarding other tables
    for col in interestCols:
        # prepare condition
        for v in interestValues:
            if v[0]==interestCols[1]:
                cond = f"{interestCols[1]}={v[1]}"
                sql = sqlQueryGen(interestCols[0], interestCols[1], cond)
                queries.append(sql)
    # executing attack
    query = {}
    query['db'] = "anonDb"
    print("\nInfo >>> Launching attack ...\n")
    print(f"... {len(queries)} SQL queries to execute")
    for q in queries:
        query['sql'] = q
        attack.askAttack(query)
    print("... getting replies")
    while True:
        reply = attack.getAttack()
        print(f"... acquiring knowledge > {reply['stillToCome']} yet to come")
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
            print("# DEBUG: 01")
            try:
                attack.askClaim(spec, claim=True)
            except:
                continue
        #claim = attack.getClaim()
        print("# DEBUG: 02")
        while True:
            claim = attack.getClaim()
            print("# DEBUG: 03")
            if claim["stillToCome"]==0:
                break
    # Compute and display score
    print("# DEBUG: 04")
    result = attack.getResults()
    print("# DEBUG: 05")
    gda_score = gdaScores(result)
    print("# DEBUG: 06")
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
        "criteria": "linkability"
    },
    'anonTypes': [
        #["no_anon"],
        #["pseudonymization", "latest"],
        #["diffix","latest"],
        #["diffix","v19_1_0"],
        #["k_anonymization","naive","k_2"],
        #["k_anonymization","naive","k_5"],
        #["pseudonymization","colSuppression"], # problem to investigate
        #["pseudonymization","kanon","k_2"],
        ["pseudonymization","kanon","k_5"]
    ],
    'tables': [
        #['banking','accounts'],
        #['banking','loans'],
        #['banking','transactions'],
        ['taxi','rides'],
        #['census','persons'],
        #['scihub','downloads']
    ]
}

# set general configuration parameters
paramsList = setupGdaAttackParameters(config)
params = paramsList[0]

# launch attack
verbose = False
ramyAttack03(params, verbose)
