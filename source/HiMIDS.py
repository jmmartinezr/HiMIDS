from simpletransformers.classification import ClassificationModel, ClassificationArgs
import pandas as pd
import numpy as np
import torch 
import joblib
from sklearn.ensemble import RandomForestClassifier
from utils import readData, analyzeTrafic
#-----------------LOADING LABELS----------------------
binaryLabelDictionary = {0: "Benign", 1: "Malicious"}
maliciousLabelDictionary = {0: 'Slowloris', 1: 'SlowHTTPTest', 2: 'DoSHulk', 3: 'Goldeneye', 4: 'Heartbleed', 5: 'DDoS', 6: 'PortScan', 7: 'Bot', 8: 'Infiltration',
                            9: 'FTP-BruteForce', 10: 'SSH-Bruteforce', 11: 'UDP', 12: 'MSSQL', 13: 'Portmap', 14: 'Syn', 15: 'NetBIOS', 16: 'UDPLag', 17: 'LDAP', 
                            18: 'DrDoS_DNS', 19: 'WebDDoS', 20: 'TFTP', 21: 'DrDoS_UDP', 22: 'DrDoS_SNMP', 23: 'DrDoS_NetBIOS', 24: 'DrDoS_LDAP', 25: 'DrDoS_MSSQL',
                            26: 'DrDoS_NTP'}
#-----------------LOADING MODELS------------------
trafficTypeModel = joblib.load("./models/trafficTypeModel.joblib")
attackTypeModel = ClassificationModel('bert','./models/attackTypeModel')

def analizarTrafico():
    print("Type the route (relative or absolute) of the file with data to analyze.")
    print('Type "return" to return to the previous step. ')
    route = input("> ")
    if route == "return":
        return 0
    else:
        print("Loading data...")
        variables = analyzeTrafic(route)
        print("Checking whether traffic is benign or malicious...")
        prediction = trafficTypeModel.predict(variables)
        malicious = []
        count = 0
        print("Results: ")
        for element in prediction:
            print("Connection "+ str(count)+ ": " + binaryLabelDictionary[element])
            if element == 1:
                malicious.append(variables[count])
            count += 1
        if len(malicious) == 0:
            print("No malicious traffic was detected.")
            return 0
        else:
            print("Checking the family of attacks for malicious traffic...")
            stringVariable = []
            for example in malicious:
                dataString = ""
                for element in example:
                    dataString += str(element)
                stringVariable.append(dataString)
            result, output = attackTypeModel.predict(stringVariable)
            count = 0
            for element in result:
                print("Instance " + str(count)+ ": " + maliciousLabelDictionary[element])
                count +=1
            return 0

def trainTrafficType():
    print("Type the route (relative or absolute) of the file with data to train the TrafficType model.")
    print('Type "return" to return to the previous step. ')
    route = input("> ")
    if route == "return":
        return 0
    else:
        print("Loading data...")
        variables, labels, labelDictionary = readData(route, "BinaryProblem")
        variables = torch.tensor(variables)
        labels = torch.tensor(labels)
        
        print("Training model...")
        trafficTypeModel.fit(variables, np.ravel(labels))
        
        print("Saving changes...")
        joblib.dump(trafficTypeModel, "./models/trafficTypeModel.joblib", compress = 3)
        
        print("Model updated.")
        return 0


def trainAttackType():
    print("Type the route (relative or absolute) of the file with data to train the AttackType model.")
    print('Type "return" to return to the previous step. ')
    route = input("> ")
    if route == "return":
        return 0
    else:
        print("Loading data...")
        variables, labels, labelDictionary = readData(route, "MaliciousOnly")
        stringVariable = []
        for example in variables:
            dataString = ""
            for element in example:
                dataString += str(element)
            stringVariable.append(dataString)
        
        data = pd.DataFrame(stringVariable, columns=["Features"])
        data["labels"] = labels

        print("Training model...")
        attackTypeModel.train_model(data)

        print("Saving changes...")
        attackTypeModel.model.save_pretrained("./models/attackTypeModel")
        attackTypeModel.tokenizer.save_pretrained("./models/attackTypeModel")
        attackTypeModel.config.save_pretrained("./models/attackTypeModel")
        
        print("Model updated.")
        return 0



# ---------------- MAIN ------------------
if __name__ == "__main__":
    flag = False
    while flag == False:
        print("\nType the number of the action to be taken.\n")
        print("1. Analyze traffic")
        print("2. Train TrafficType model.")
        print("3. Train AttackType model.")
        print("4. Exit")
        answer = input("> ")
        if answer == "1":
            analizarTrafico()
        else: 
            if answer == "2":
                trainTrafficType()
            else:
                if answer == "3":
                    trainAttackType()
                else: 
                    if answer == "4":
                        flag = True
                    else: 
                        print("Please try again.")
        