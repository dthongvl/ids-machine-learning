"""K-Means Classifier"""
import collections
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import minmax_scale
import matplotlib.pyplot as plt
from default_clf import DefaultNSL, COL_NAMES, ATTACKS


class KMeansNSL(DefaultNSL):

    def __init__(self):
        super(KMeansNSL, self).__init__()
        self.cols = None
        self.clusters = {0: None, 1: None, 2: None, 3: None}

    def load_training_data(self, filepath):
        data, labels = self.load_data(filepath)
        self.cols = data.columns
        self.training = [data, labels]

    def load_test_data(self, filepath):
        data, labels = self.load_data(filepath)
        map_data = pd.DataFrame(columns=self.cols)
        map_data = map_data.append(data)
        data = map_data.fillna(0)
        self.testing = [data[self.cols], labels]

    @staticmethod
    def load_data(filepath):
        data = pd.read_csv(filepath, names=COL_NAMES, index_col=False)
        # Shuffle data
        data = data.sample(frac=1).reset_index(drop=True)
        NOM_IND = [1, 2, 3]
        BIN_IND = [6, 11, 13, 14, 20, 21]
        # Need to find the numerical columns for normalization
        NUM_IND = list(set(range(40)).difference(NOM_IND).difference(BIN_IND))

        # Scale all numerical data to [0-1]
        data.iloc[:, NUM_IND] = minmax_scale(data.iloc[:, NUM_IND])
        labels = data['labels']
        del data['labels']
        data = pd.get_dummies(data)
        return [data, labels]

    def train_clf(self):
        self.clf = KMeans(n_clusters=4, init='random').fit(self.training[0])
        self.set_categories()

    def test_clf(self, train=False):
        if train:
            data, labels = self.training
        else:
            data, labels = self.testing
        test_preds = self.clf.predict(data)
        test_preds = [self.clusters[x] for x in test_preds]
        bin_labels = labels.apply(lambda x: x if x == 'normal' else 'anomaly')
        test_acc = sum(test_preds == bin_labels)/(len(test_preds) * 1.0)
        return [test_preds, test_acc]

    def set_categories(self):
        labels = self.training[1]
        bin_labels = labels.apply(lambda x: x if x == 'normal' else 'anomaly')
        clust_preds = self.clf.labels_
        count = collections.Counter(zip(clust_preds, bin_labels))
        num = [0, 0, 0, 0]
        for k, val in count.items():
            clust = k[0]
            if val > num[clust]:
                num[clust] = val
                self.clusters[clust] = k[1]

    def predict(self, packet):
        data = pd.DataFrame([packet], columns=COL_NAMES)

        data = data.sample(frac=1).reset_index(drop=True)
        NOM_IND = [1, 2, 3]
        BIN_IND = [6, 11, 13, 14, 20, 21]

        NUM_IND = list(set(range(40)).difference(NOM_IND).difference(BIN_IND))

        data.iloc[:, NUM_IND] = minmax_scale(data.iloc[:, NUM_IND])
        del data['labels']
        data = pd.get_dummies(data)

        map_data = pd.DataFrame(columns=self.cols)
        map_data = map_data.append(data)
        data = map_data.fillna(0)

        predict = self.clf.predict(data[self.cols])
        predict = [self.clusters[x] for x in predict]
        return predict[0]
