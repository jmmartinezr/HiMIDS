import torch


INFINITY = 1387000000000000000000000000000000.0

def fixName(string):
    """
    Removes \n from input string.
    """
    return "".join(string.splitlines())


def readData(dataFile, executionMode):
    """
    Receives input data and readies it for training of a model.
    """
    variables = []
    labels = []
    labelDictionary = {}
    labelCount = 0
    if executionMode == "ClassicProblem":
        with open(dataFile) as data:
            for line in data:
                aux = line.split(",")
                label = fixName(aux.pop())
                if label in labelDictionary:
                    labels.append(labelDictionary[label])
                else: 
                    labelDictionary[label] = labelCount
                    labels.append(labelCount)
                    labelCount+=1
                prunedData = []
                for variable in aux:
                    if variable == "NaN" or variable == "?":
                        prunedData.append(-1.0)
                    else:
                        if variable == "Infinity":
                            prunedData.append(INFINITY)
                        else:
                            prunedData.append(float(variable))
                variables.append(prunedData)
    else:
        if executionMode == "BinaryProblem":
            labelDictionary["Benign"] = 0
            labelDictionary["Malicious"] = 1
            with open(dataFile) as data:
                for line in data:
                    aux = line.split(",")
                    label = fixName(aux.pop())
                    if (label != "Benign"):
                        label = "Malicious"
                    labels.append(labelDictionary[label])
                    prunedData = []
                    for variable in aux:
                        if variable == "NaN" or variable == "?":
                            prunedData.append(-1.0)
                        else:
                            if variable == "Infinity":
                                prunedData.append(INFINITY)
                            else:
                                prunedData.append(float(variable))
                    variables.append(prunedData)
        else:
            if executionMode == "MaliciousOnly":
                with open(dataFile) as data:
                    for line in data:
                        aux = line.split(",")
                        label = fixName(aux.pop())
                        if (label != "Benign"):
                            if label in labelDictionary:
                                labels.append(labelDictionary[label])
                            else: 
                                labelDictionary[label] = labelCount
                                labels.append(labelCount)
                                labelCount+=1
                            prunedData = []
                            for variable in aux:
                                if variable == "NaN" or variable == "?":
                                    prunedData.append(-1.0)
                                else:
                                    if variable == "Infinity":
                                        prunedData.append(INFINITY)
                                    else:
                                        prunedData.append(float(variable))
                            variables.append(prunedData)
    return variables,labels,labelDictionary


def analyzeTrafic(dataFile):
    """
    Receives input data and readies it for traffic analysis.
    """
    variables = []
    with open(dataFile) as data:
        for line in data:
            aux = line.split(",")
            prunedData = []
            for variable in aux:
                if variable == "NaN" or variable == "?":
                    prunedData.append(-1.0)
                else:
                    if variable == "Infinity":
                        prunedData.append(INFINITY)
                    else:
                        prunedData.append(float(variable))
            variables.append(prunedData)
    return variables