from kmeans.kmeans_nsl import KMeansNSL

if __name__ == '__main__':
    kmean = KMeansNSL()
    kmean.load_training_data('datasets/KDDTrain+.csv')
    kmean.load_test_data('datasets/KDDTest+.csv')
    kmean.train_clf()
    kmean.evaluate_results()
