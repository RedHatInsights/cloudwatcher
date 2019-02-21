import os
import logging
import sys
import json
import utils

from flask import Flask, request, Response
from logstash_formatter import LogstashFormatterV1


LISTEN_PORT = os.getenv('LISTEN_PORT', 8080)

LOGLEVEL = os.getenv("LOGLEVEL", "INFO")
if any("KUBERNETES" in k for k in os.environ):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(LogstashFormatterV1())
    logging.root.setLevel(LOGLEVEL)
    logging.root.addHandler(handler)
else:
    logging.basicConfig(
        level=LOGLEVEL,
        format="%(threadName)s %(levelname)s %(name)s - %(message)s"
    )

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

logger = logging.getLogger('cloudwatcher')

app = Flask(__name__)


@app.route('/cloudwatch', methods=['POST'])
def cloudwatch_post():
    data = request.data
    sns_validation = utils.Validator()
    notification = sns_validation.handle(data)
    if notification.is_valid:
        logger.info(notification.message)
        logger.info(json.loads(notification.message))
    else:
        logger.error('Invalid Signature. Message Rejected')
        return Response('{"received": "failure"}', status=400, mimetype='application/json')
    return Response('{"received": "ok"}', status=200, mimetype='application/json')


@app.route('/', methods=['GET'])
def root():
    return 'boop'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT)
