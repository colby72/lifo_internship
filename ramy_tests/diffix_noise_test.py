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

def diffix_noise(params, verbose):
    # Check on parameters
    print("########## Parameters passed ##########")
    pp.pprint(params)
    # Attack setup
    attack = gdaAttack(params)
    attack.unsetVerbose()
    print("\nInfo >>> Attack Class created\n")
    # Back to target table ...
    table = attack.getAttackTableName()
    rawColNames = attack.getColNames(dbType="rawDb")
    anonColNames = attack.getColNames(dbType="anonDb")
    # Query
    sql = f"SELECT avg(duration), count(*) FROM {table} WHERE gender='Male'"
    query = {}
    query['db'] = "rawDb"
    query['sql'] = sql
    print("########## Query Info ##########")
    print(f"Table : {table} > {query['db']}")
    print(f"Query : {sql}")
    # Attack
    print("\nInfo >>> Launching attack ...")
    attack.askExplore(query)
    while True:
        reply = attack.getExplore()
        print(f"... acquiring knowledge > {reply['stillToCome']} yet to come")
        if reply["stillToCome"]==0:
            break
    print("\n########## Query Result ##########")
    if "answer" in reply.keys():
        print(f"Result : {reply['answer']}")
    else:
        print("Error >>> Reply ...")
        pp.pprint(reply)
    # Compute and display score
    result = attack.getResults()
    gda_score = gdaScores(result)
    print("\nInfo >>> Score Class created\n")
    #print("########## Attack score ##########")
    score = gda_score.getScores()
    #pp.pprint(score)
    # Abschliessung
    attack.cleanUp()
    final_result = finishGdaAttack(params, score)
    return None


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


config = {
    "basic": {
        "attackType": "Diffix Noise Test",
        "criteria": "singlingOut"
        #"criteria": "inference"
        #"criteria": "linkability"
    },
    'anonTypes': [
        #["no_anon"],
        #["pseudonymization", "latest"],
        ["diffix","latest"],
        ["diffix","v19_1_0"],
        ["k_anonymization","naive","k_2"],
        ["k_anonymization","naive","k_5"],
        ["pseudonymization","colSuppression"], # problem to investigate
        ["pseudonymization","kanon","k_2"],
        ["pseudonymization","kanon","k_5"]
    ],
    'tables': [
        #['banking','accounts'],
        ['banking','loans'],
        #['banking','transactions'],
        #['taxi','rides'],
        #['census','persons'],
        #['scihub','downloads']
    ]
}

# set general configuration parameters
paramsList = setupGdaAttackParameters(config)
params = paramsList[0]

# launch attack
verbose = False
diffix_noise(params, verbose)
