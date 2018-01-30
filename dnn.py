from enum import Enum
from os.path import isdir

import tensorflow as tf

from packet_parser import DNNDataset, DNNPacket


class DatasetLabel(Enum):
    NORMAL = 0
    DDOS = 1


# DNN parameters
hidden_units = [20, 20, 20]
dnn_model_dir = "dnn_classifier/training_models"
feature_columns = [tf.feature_column.numeric_column("x", shape=[len(DNNPacket().dict)])]
dnn_classifier = tf.estimator.DNNClassifier(feature_columns=feature_columns,
                                            hidden_units=hidden_units,
                                            n_classes=len(DatasetLabel),
                                            model_dir=dnn_model_dir)


def train(normal_dataset=None, ddos_dataset=None, training_steps=1000):
    if normal_dataset is None or isinstance(normal_dataset, DNNDataset) is False:
        return "Base de dados da rede local invalida"

    if ddos_dataset is None or isinstance(ddos_dataset, DNNDataset) is False:
        return "Base de dados de DDoS invalida"

    cross_dataset = DNNDataset.cross(normal_dataset, ddos_dataset)

    train_numpy, train_labels, test_numpy, test_labels = cross_dataset.to_numpy(split_for_training=True)

    train_input_fn = tf.estimator.inputs.numpy_input_fn(x={"x": train_numpy},
                                                        y=train_labels,
                                                        num_epochs=None,
                                                        shuffle=True)

    dnn_classifier.train(input_fn=train_input_fn, steps=training_steps)

    test_input_fn = tf.estimator.inputs.numpy_input_fn(x={"x": test_numpy},
                                                       y=test_labels,
                                                       num_epochs=1,
                                                       shuffle=False)

    evaluate_result = dnn_classifier.evaluate(test_input_fn)
    dnn_accuracy = evaluate_result["accuracy"] * 100
    return "Rede neural foi treinada com {0:.2f}% de precisão".format(dnn_accuracy)


def predict_network_traffic(live_dataset=None):
    if live_dataset is None or isinstance(live_dataset, DNNDataset) is False:
        print("predict_network_traffic: Dataset inválido")
        return []

    if not is_dnn_trained():
        print("A rede ainda não foi treinada")
        return []

    packet_list, _ = live_dataset.to_numpy(split_for_training=False)

    numpy_input_fn = tf.estimator.inputs.numpy_input_fn(x={'x': packet_list},
                                                        shuffle=False,
                                                        num_epochs=1)

    predictions = list(dnn_classifier.predict(input_fn=numpy_input_fn))

    return [p["class_ids"][0] for p in predictions]


def is_dnn_trained():
    return isdir(dnn_model_dir)
