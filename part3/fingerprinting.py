import numpy as np
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn import metrics
from scapy.all import *


def classify(train_features, train_labels, test_features, test_labels):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions

def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    all_preds = []
    all_true = []

    # For stats per fold
    accs, f1_macros, f1_micros, prec_macros, prec_micros = [], [], [], [], []

    for train_idx, test_idx in kf.split(features, labels):
        X_train, X_test = features[train_idx], features[test_idx]
        y_train, y_test = labels[train_idx], labels[test_idx]

        preds = classify(X_train, y_train, X_test, y_test)

        all_preds.extend(preds)
        all_true.extend(y_test)

        accs.append(metrics.accuracy_score(y_test, preds))
        f1_macros.append(metrics.f1_score(y_test, preds, average="macro", zero_division=0))
        f1_micros.append(metrics.f1_score(y_test, preds, average="micro", zero_division=0))
        prec_macros.append(metrics.precision_score(y_test, preds, average="macro", zero_division=0))
        prec_micros.append(metrics.precision_score(y_test, preds, average="micro", zero_division=0))

    # Final results
    print("Cross-validation results:")
    print(f"  Accuracy         : {np.mean(accs):.4f}")
    print(f"  Precision (macro): {np.mean(prec_macros):.4f}")
    print(f"  Precision (micro): {np.mean(prec_micros):.4f}")
    print(f"  F1-score (macro) : {np.mean(f1_macros):.4f}")
    print(f"  F1-score (micro) : {np.mean(f1_micros):.4f}")
    print("\nConfusion Matrix:")
    print(metrics.confusion_matrix(all_true, all_preds))

    return {
        "accuracy": np.mean(accs),
        "precision_macro": np.mean(prec_macros),
        "precision_micro": np.mean(prec_micros),
        "f1_macro": np.mean(f1_macros),
        "f1_micro": np.mean(f1_micros),
        "confusion_matrix": metrics.confusion_matrix(all_true, all_preds)
    }


def timing(pkts):
    if len(pkts) > 1:
        times = [float(p.time) for p in pkts]
        d = np.diff(times)
        return [np.max(d), np.std(d)]
    return [0, 0]


def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """


    features = []
    labels = []
    nb_rounds = 100

    for cell in range(1, 101):
        #for run in list(range(100, 160)) + list(range(20)):
        for run in range(1, nb_rounds+1):
            path = f"tor_pcap/generate_data_{run}_requests_cell_{cell}.pcap"
            if not os.path.exists(path):
                print(path ,"DOES NOT EXIST")
                continue
            try:
                packets = rdpcap(path)
            except:
                continue

            tcp_packets = [p for p in packets if p.haslayer(TCP) and p.haslayer(IP)]

            # heuristic separation of flows
            outgoing, incoming = [], []
            for s in set(p[TCP].sport for p in tcp_packets):
                same_sport = [p for p in tcp_packets if p[TCP].sport == s]
                if s > 40000 and len(same_sport) > len(outgoing):
                    outgoing = same_sport
                elif s <= 40000 and len(same_sport) > len(incoming):
                    incoming = same_sport

            if not outgoing or not incoming:
                continue

            feat = []

            # number of packets
            feat.append(len(outgoing))
            feat.append(len(incoming))

            # Sizes
            o_len = [len(p) for p in outgoing]
            i_len = [len(p) for p in incoming]

            for arr in [o_len, i_len]:
                feat += [np.sum(arr), np.mean(arr), np.min(arr),
                         np.max(arr), np.std(arr)]

            # Timings
            feat += timing(outgoing)
            feat += timing(incoming)

            # Durations
            feat.append(outgoing[-1].time - outgoing[0].time)
            feat.append(incoming[-1].time - incoming[0].time)

            # TCP Flags
            for flag in [0x01, 0x02, 0x08, 0x10]:  # FIN, SYN, PSH, ACK
                feat.append(sum(p[TCP].flags & flag > 0 for p in outgoing))
                feat.append(sum(p[TCP].flags & flag > 0 for p in incoming))

            features.append(feat)
            labels.append(cell)

    return features, labels
        
def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """


    features, labels = load_data()
    print(f"Loaded {len(features)} traces.")
    perform_crossval(features, labels, folds=10) #folds=10 !
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)