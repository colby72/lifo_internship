# @author: Ramy CHEMAK
# @university: INSA Centre Val de Loire et Université d'Orléans
# @laboratory: Laboratoire d'Informatique Fondamentale d'Orléans (LIFO-EA 4022)


import pprint
import random

from gdascore.gdaAttack import gdaAttack
from gdascore.gdaTools import setupGdaAttackParameters
from gdascore.gdaScore import gdaScores
from gdascore.gdaTools import setupGdaAttackParameters, comma_ize, finishGdaAttack

pp = pprint.PrettyPrinter(indent=4)

# A test attack
# The attack make queries to a database, specifically to a sensitive attribute
# We are looking for a users with specific value v for this attribute
# We request all records corresponding to the value v, and try to identify them
# It is designed to work against raw and pseudonymized data

def ramyAttack01(params):
    # Check on parameters
    print("########## Parameters passed ##########")
    pp.pprint(params)
    # Attack setup
    attack = gdaAttack(params)
    print("\nInfo >>> Attack Class created\n")
    table = attack.getAttackTableName()
    print("### Table ###")
    pp.pprint(table)
    rawColNames = attack.getColNames(dbType="rawDb")
    print("### Raw Cols ###")
    pp.pprint(rawColNames)
    anonColNames = attack.getColNames(dbType="anonDb")
    print("### Anon Cols ###")
    pp.pprint(anonColNames)
    # set attack specific parameters
    searchedCol = random.choice(rawColNames)
    publicValues = attack.getPublicColValues("gender", table)
    print(f"\nInfo >>> Randomly selected column : {searchedCol}\n")
    print("### Column Values ###")
    pp.pprint(publicValues)
    searchedValue = ""
    condition = "gender = 'Male'"
    # Define SQL queries
    sql = "SELECT "
    sql += comma_ize(rawColNames, lastComma=False)
    sql += " FROM " + table
    sql += " WHERE " + condition
    query = {}
    query['sql'] = sql
    query['db'] = "rawDb"
    # executing attack
    print("\nInfo >>> Launching attack ...\n")
    attack.askAttack(query)
    reply = attack.getAttack()
    pp.pprint(reply)
    # Compute and display score
    result = attack.getResults()
    gda_score = gdaScores(result)
    print("\nInfo >>> Score Class created\n")
    print("########## Attack reply ##########")
    score = gda_score.getScores()
    pp.pprint(score)
    # Abschliessung
    attack.cleanUp()
    final_result = finishGdaAttack(params, score)


config = {
    "basic": {
        "attackType": "Ramy Test Attack",
        "criteria": "singlingOut"
    },
    'anonTypes': [
        ["no_anon"],
        ["pseudonymization", "latest"]
    ],
    'tables': [ ['banking','accounts'] ]
}

# set general configuration parameters
paramsList = setupGdaAttackParameters(config)
params = paramsList[0]

# launch attack
ramyAttack01(params)
