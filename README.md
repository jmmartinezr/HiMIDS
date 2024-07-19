# HiMIDS
### Introduction
This is the repository for the Hierarchical Model for Intrusion Detection Systems (HiMDIDS). It includes the source code for the model, as well as the pre-processed datasets used to train it.
Datasets can be found in the folder of the same name.
Source code can be found in the folder "source".

### HiMIDS
Cybersecurity mechanisms must be improved in order to keep up with the amount of new attacks and specific exploits that keep appearing as technology develops. Since classic paradigms are proven to be insufficient when it comes to the detection of newer attacks, making use of newer technologies, such as deep learning, to improve the scalability and functionality of previous mechanisms will be key to defend from attacks.

In order to be able to detect attacks in a more efficient manner, a hierarchical model is proposed. By using this method, the model is able to detect whether a given system is under attack, moreover discriminating with great accuracy the specific family said attack belongs to.

The HiMIDS model first receives data regarding different traffic which was used to train both of the models used in subsequent stages. In order to minimize bias and properly assess each model, they were trained and evaluated applying stratified cross validation, so that for every iteration of the loop, the entire dataset was divided in five subsets, referred to as folds, which contain a distribution of classes that is as similar as possible to the original data. Four of these folds were used as the training set and the remaining one was used as the test set.

This training process is used for both models used in the following stages. The first stage makes use of a RandomForest-based algorithm which can filter all connections discriminating between benign and malicious ones regardless of the different kinds of attack. If all traffic is classified as benign, the model will stop its execution, since only malicious predictions are stored and then forwarded for the second stage of analysis, where a Transformer-based model will attempt to differentiate between different kinds of malicious connection, attempting to determine the general family of the attack (i.e DDoS) that said traffic belongs to. This second stage will only take place if the first stage has detected the data as malicious, and will not be taken into consideration otherwise.

Using such a model offers several advantages. First, it allows us to make good use of the stronger points of each model used. Furthermore, if a model is particularly suited for a given task in the workflow, it can be relegated to doing that task specifically, leaving the rest to another model. 

The HiMIDS algorithm is novelty when it comes to the monitoring of dangerous behavior. Albeit models are used for either general attacks or specific families, the two kinds are seldom seen working together. Combining this strategy with newer classification techniques, such as ensemble models or deep learning, the objective is to find a new model that can improve the results of state of the art models whilst also being able to perform both as a general model and a specific one.

The detection based on two stages is also more efficient. Binary problems are easier to solve, and as such, take less time. As the first stage consists on detecting whether a connection is benign or malicious, the model only needs to continue running if the traffic is classified as malicious, which makes it so that it is more efficient and less energy-consuming.

### Implementation
In an attempt to easen the implementation and testing of the Transformer models that the second part of HiMIDS are based around, the Pytorch framework has been used. Another library, SimpleTransformers, is used as well, as it is designed to easily use Transformers provided by HuggingFace with PyTorch code.

Lastly, RandomForest is not a deep learning algorithm, and thus it cannot be implemented by using PyTorch. However, since it is being used, it will instead be implemented using scikit-learn, as it is compatible with PyTorch tensors and makes the code considerably simpler. 
