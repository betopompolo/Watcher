import datetime
import time
from urllib.request import urlopen

from flask import Flask, render_template, jsonify, redirect, request
from werkzeug.utils import secure_filename

import dnn
from DNNThread import DNNThread

DDOS_DATASET_FOLDER = 'capture_data/ddos/'
ALLOWED_EXTENSIONS = {'pcap'}
ddos_dataset = dnn.DNNDataset()
ddos_dataset_filename = None
normal_dataset = dnn.DNNDataset()

live_dataset = dnn.DNNDataset()
PREDICT_THRESHOLD = 1000
ddos_percentage = 0

# Background Threads
sniffing_thread = None
predict_thread = None

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = DDOS_DATASET_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Setting max upload size (100 mb)


def check_connection():
    for timeout in [1, 5, 10]:
        try:
            urlopen('https://www.google.com.br/', timeout=timeout)
        except Exception:
            raise Exception('Não há conexão com a internet')


@app.route('/')
def index():
    try:
        check_connection()
        pps_list = live_dataset.pps_list
        pps = pps_list[-1]
        is_dnn_trained = str(dnn.is_dnn_trained()).lower()
        resume_background_threads()
        return render_template('index.html', pps=pps, traffic_data=pps_list, is_dnn_trained=is_dnn_trained)

    except Exception as e:
        return render_template('error.html', error_msg=str(e))


@app.route('/_update_home')
def update_home():
    try:
        last_point = list(live_dataset.pps_list[-1])
        last_point[0] = datetime.datetime.now().strftime('%H:%M:%S')
        pps = last_point[1]
        return jsonify(traffic_data=tuple(last_point), pps=pps, ddos=ddos_percentage)
    except Exception as e:
        return jsonify(error_msg=str(e))


@app.route('/dnn_train')
def dnn_train():
    try:
        if dnn.is_dnn_trained():
            return redirect('/')
        else:
            pause_background_threads()
            return render_template('dnn_train.html')
    except Exception as e:
        return render_template('error.html', error_msg=str(e))


@app.route('/dnn_train/_dataset_input', methods=['POST'])
def dataset_input():
    try:
        import os
        global ddos_dataset_filename

        dataset = request.files['ddosinput']

        if dataset.filename is "":
            raise Exception("Nenhum arquivo selecionado")

        if dataset and allowed_file_extension(dataset.filename):
            filename = secure_filename(dataset.filename)
            ddos_dataset_filename = app.config["UPLOAD_FOLDER"] + filename
            dataset.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            return jsonify()

        else:
            raise Exception("Erro ao carregar o arquivo")
    except Exception as e:
        return error_response(str(e))


@app.route("/dnn_train/_start_train")
def start_train():
    try:
        train_status = dnn.train(normal_dataset, ddos_dataset)
        print("train status:", train_status)
        return jsonify(train_status=train_status)

    except Exception as e:
        print("train error:", str(e))
        return error_response(str(e))


@app.route('/dnn_train/_sniff')
def sniff_normal_dataset():
    try:
        ddos_dataset.from_file(ddos_dataset_filename,
                               dnn.DatasetLabel.DDOS)
        normal_dataset.from_local_network(packet_count=ddos_dataset.length,
                                          dataset_label=dnn.DatasetLabel.NORMAL)
        return jsonify()

    except Exception as e:
        return error_response(str(e))


def allowed_file_extension(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def error_response(error_msg):
    error = jsonify(error_msg=error_msg)
    error.status_code = 505
    return error


def predict_traffic():
    try:
        if live_dataset.length < PREDICT_THRESHOLD:
            return

        global ddos_percentage
        live_dataset.locked = True
        live_dataset.update_pps()
        ddos_count = sum([dnn.DatasetLabel(result).value == dnn.DatasetLabel.DDOS.value
                          for result
                          in dnn.predict_network_traffic(live_dataset)])
        try:
            ddos_percentage = (ddos_count / live_dataset.length) * 100
        except ArithmeticError:
            ddos_percentage = 0

        print("DDoS: {}".format(ddos_percentage))
        live_dataset.dnn_packet_list.clear()
    finally:
        live_dataset.locked = False
        time.sleep(1)


def capture_traffic():
    live_dataset.from_local_network(dnn.DatasetLabel.NORMAL)


def create_background_threads():
    global sniffing_thread, predict_thread
    sniffing_thread = DNNThread(action=capture_traffic)
    sniffing_thread.start()
    predict_thread = DNNThread(action=predict_traffic)
    predict_thread.start()


def resume_background_threads():
    sniffing_thread.pause = False
    predict_thread.pause = False


def pause_background_threads():
    sniffing_thread.pause = True
    predict_thread.pause = True


if __name__ == '__main__':
    create_background_threads()
    app.run(host='0.0.0.0')
