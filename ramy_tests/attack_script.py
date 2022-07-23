# @author: Ramy CHEMAK
# @university: INSA Centre Val de Loire et Université d'Orléans
# @laboratory: Laboratoire d'Informatique Fondamentale d'Orléans (LIFO-EA 4022)


from noise_exploitation_algos import *
from manual import extract_record
from noise_exploitation_inference import *
from pyfiglet import Figlet, figlet_format
import pprint

from gdascore.gdaAttack import gdaAttack
from gdascore.gdaTools import setupGdaAttackParameters
from gdascore.gdaScore import gdaScores
from gdascore.gdaTools import setupGdaAttackParameters, comma_ize, finishGdaAttack

pp = pprint.PrettyPrinter(indent=4)


config = {
    "basic": {
        "attackType": "Differential noise-exploitation Attack",
        "criteria": "inference"
    },
    'anonTypes': [
        ["no_anon"],
        ["pseudonymization", "latest"],
        ["diffix","latest"],
        ["diffix","v19_1_0"],
        ["k_anonymization","naive","k_2"],
        ["k_anonymization","naive","k_5"],
        ["pseudonymization","colSuppression"],
        ["pseudonymization","kanon","k_2"],
        ["pseudonymization","kanon","k_5"]
    ],
    'tables': [
        ['banking','accounts'],
        #['banking','loans'],
        #['banking','transactions'],
        #['taxi','rides'],
        #['census','persons'],
        #['scihub','downloads']
    ]
}


anon_types_all = [
    ["no_anon"],
    ["pseudonymization", "latest"],
    ["diffix","latest"],
    ["diffix","v19_1_0"],
    ["k_anonymization","naive","k_2"],
    ["k_anonymization","naive","k_5"],
    ["pseudonymization","colSuppression"],
    ["pseudonymization","kanon","k_2"],
    ["pseudonymization","kanon","k_5"]
]

tables_all = [
    ['banking','accounts'],
    ['banking','loans'],
    ['banking','transactions'],
    ['taxi','rides'],
    ['census','persons'],
    ['scihub','downloads']
]


#fig = Figlet(font="slant")
#print(fig.renderText("Differential noise-exploitation Attack"))
#print(figlet_format("Differential noise-exploitation Attack", font="digital"))
print("\n----------------------------------------------")
print("--- Diffix noise-exploitation Attack ---")
print("----------------------------------------------")

# set verbose
verbose = False

# select attack type
print("\nList of attack types :\n")
print("1- Differential attack")
print("2- Cloning attack")
print("3- Greedy cloning attack")
attack_type = input("\nSelect choice > ")
attack_type = int(attack_type)

# select anonymization method
print("\nList of anonymization method :\n")
print("0- Automatic")
print("1- no_anon")
print("2- pseudonymization, latest")
print("3- diffix, latest")
print("4- diffix, v19_1_0")
print("5- k_anonymization, naive, k_2")
print("6- k_anonymization, naive, k_5")
print("7- pseudonymization, colSuppression")
print("8- pseudonymization, kanon, k_2")
print("9- pseudonymization, kanon, k_5")
anon_type = input("\nSelect choice > ")
anon_type = int(anon_type)

# select table
print("\nList of available DBs and tables :\n")
print("0- Automatic")
print("1- DB: banking\t Table: accounts")
print("2- DB: banking\t Table: loans")
print("3- DB: banking\t Table: transactions")
print("4- DB: taxi\t Table: rides")
print("5- DB: census\t Table: persons")
print("6- DB: scihub\t Table: downloads")
target_table = input("\nSelect choice (0 for all) > ")
target_table = int(target_table)

if target_table==0:
    for i in range(1, 7):
        launch_targeted_attack(attack_type, i, anon_type)
else:
    launch_targeted_attack(attack_type, target_table, anon_type)


def launch_targeted_attack(type=1, tab=1, anon="no_anon"):
    """
    Params :
    'type' is the attack variety among noise-exploitation family
    'tab' referes to the targeted table
    'anon' refers to the anonymization method
    """
    # specify target configuration
    # set anonymization algorithm
    config['anonTypes'][0] = anon_types_all[anon]
    # set target table
    config['tables'][0] = tables_all[tab]
    # set attack type
    if attack_type == 1:
        attack_type = "differential"
        config['basic']['attackType'] = "Differential noise-exploitation Attack"
        # set appropriate specific parameters
        #scheme = get_database_scheme(params, verbose)
    elif attack_type == 2:
        attack_type = "cloning"
        config['basic']['attackType'] = "Cloning noise-exploitation Attack"
    elif attack_type == 3:
        attack_type = "greedy"
        config['basic']['attackType'] = "Greedy cloning Attack"
    # set general configuration parameters
    paramsList = setupGdaAttackParameters(config)
    params = paramsList[0]
    # launch attack
    print(f"\nInfo >>> Launching {attack_type} attack ...")
    print(f"... targeting {config['tables'][0]} anonymized with {config['anonTypes'][0]}\n")
    noise_exploitation_attack(attack_type, params, verbose)


def differential_automatic():
    attack_type = "differential"
    config['basic']['attackType'] = "Differential noise-exploitation Attack"
    for tab in tables_all:
        config['tables'][0] = tab
        for anon in anon_types_all:
            config['anonTypes'][0] = anon
            # set general configuration parameters
            paramsList = setupGdaAttackParameters(config)
            params = paramsList[0]
            # get scheme and gather specific parameters first
            print(f"Info >>> Getting schema for {config['tables']} ...\n")
            scheme = get_database_scheme(params, verbose)
            spec_params = [scheme[1].keys()]
            for c in scheme[0].keys():
                spec_params.append(c)
                # launch attack
                print(f"\nInfo >>> Launching {attack_type} attack ...")
                print(f"... targeting {config['tables'][0]} anonymized with {config['anonTypes'][0]}")
                print(f"... targeting column {c}\n")
                noise_exploitation_attack(attack_type, params, verbose, spec_params)
