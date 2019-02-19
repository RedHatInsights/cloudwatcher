# coding: utf-8
# coding: utf-8
# Copyright [2015] [Robert Allen]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
from __future__ import absolute_import
import json
from .notifications import SubscriptionConfirmation, UnsubscribeConfirmation, Notification
from cloudwatcher import logger

class Validator(object):
    UNSUBSCRIBE = 'unsubscribe'
    SUBSCRIBE = 'subscribe'
    DROP = 'drop'
    ACCEPT = 'accept'

    _default_options = {
        "white_list": ['arn:aws:sns:us-east-1:075747038871:test_alerts'],
        "validate_signature": True

    }

    def __init__(self):
        """

        :param options dict:
        :return:
        """
        self.options = self._default_options

    def handle(self, json_string):
        try:
            _raw = json.loads(json_string)
        except ValueError as ex:
            logger.error(ex)
            return
        if 'Type' not in _raw:
            logger.error("unknown message format unable to proceed")
            return
        if _raw['Type'] in ['SubscriptionConfirmation']:
            logger.info("SubscriptionConfirmation for TopicArn: [%s]" % _raw['TopicArn'])
            mesg = SubscriptionConfirmation(_raw, validate_signature=self.options['validate_signature'])
        elif _raw['Type'] in ['Notification']:
            logger.info("Notification for TopicArn: [%s]" % _raw['TopicArn'])
            mesg = Notification(_raw, validate_signature=self.options['validate_signature'])
        elif _raw['Type'] in ['UnsubscribeConfirmation']:
            logger.info("UnsubscribeConfirmation for TopicArn: [%s]" % _raw['TopicArn'])
            mesg = UnsubscribeConfirmation(_raw, validate_signature=self.options['validate_signature'])
        else:
            logger.error("UNKNOWN message type [%s] submitted dropping submission" % _raw['Type'])
            return
        if not mesg.is_valid:
            logger.error("INVALID message unable to authenticate MessageId:[%s]" % _raw['MessageId'])
        if not self.is_acceptable(_raw['TopicArn']):
            logger.error("UNKNOWN TopicArn [%s] message dropped" % _raw['TopicArn'])
        return mesg

    def is_acceptable(self, topic_arn):
        logger.debug("Testing validity of incoming message with TopicArn: [%s] against white_list [%s]" % (
            topic_arn, self.options['white_list']))
        if topic_arn not in self.options['white_list']:
            return False
        return True
