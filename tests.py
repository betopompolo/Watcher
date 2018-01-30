# import time
# import csv


# def save_csv(filename, packet_list):
#     import csv
#
#     with open(filename, 'x') as file:
#         wr = csv.writer(file, quoting=csv.QUOTE_ALL)
#         wr.writerow(dnn.DNNPacket().dict.keys())
#
#         for p in packet_list:
#             wr.writerow(p.dict.values())


#
# train_time = time.time()
#
# ddos_dataset = dnn.DNNDataset()
# ddos_dataset.from_folder(folder="capture_data/ddos/",
#                          dataset_label=dnn.DatasetLabel.DDOS)
#
# save_csv("ddos.csv", ddos_dataset.dnn_packet_list)
#
# normal_dataset = dnn.DNNDataset()
# normal_dataset.from_folder(folder="capture_data/", dataset_label=dnn.DatasetLabel.NORMAL)
#
# save_csv("normal.csv", normal_dataset.dnn_packet_list)
#
# train_result = dnn.train(normal_dataset=normal_dataset,
#                          ddos_dataset=ddos_dataset)
#
# print('Training time: {0:.2f} seconds\nTrain result: {1}'.format(time.time() - train_time, train_result))

# predict_dataset = dnn.DNNDataset()
#
# predict_dataset.from_file(dataset_path="capture_data/normal.pcap",
#                           dataset_label=dnn.DatasetLabel.DDOS)
#
# ddos_count = sum([dnn.DatasetLabel(result).value == dnn.DatasetLabel.DDOS.value
#                   for result
#                   in dnn.predict_network_traffic(predict_dataset)])
# normal_count = predict_dataset.length - ddos_count
# ddos_percentage = (ddos_count / predict_dataset.length) * 100
#
# print("DDoS percentage: {}%".format(ddos_percentage))
