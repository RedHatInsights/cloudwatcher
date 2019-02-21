# coding: utf-8
# Copyright [2015] [Robert Allen]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
from . import crypto
import httplib2
import json
import logging

logger = logging.getLogger('cloudwatcher')

class BaseNotification(object):
    SIGNATURE_ATTR = []

    def __init__(self, raw_message, validate_signature=True):
        """
        :param raw_message str:
        :return bool:
        """
        logger.debug("Message Recieved:\n>>BEGIN>>\n%s\n<<<END>>>" % raw_message)
        self.debug_messages = []
        self.validate_signature = validate_signature
        self.raw_message = raw_message
        self.is_valid = None
        if 'Type' not in self.raw_message:
            self.debug_messages.append("[Type] not found")
        else:
            self.type = self.raw_message['Type']
        if 'MessageId' not in self.raw_message:
            self.debug_messages.append("[MessageId] not found")
        else:
            self.type = self.raw_message['MessageId']
        if 'TopicArn' not in self.raw_message:
            self.debug_messages.append("[TopicArn] not found")
        else:
            self.type = self.raw_message['TopicArn']
        if 'Signature' not in self.raw_message:
            self.debug_messages.append("[Signature] not found")
        else:
            self.signature = self.raw_message['Signature']
        if 'SigningCertURL' not in self.raw_message:
            self.debug_messages.append("[SigningCertURL] not found")
        else:
            self.signing_cert_url = self.raw_message['SigningCertURL']
        if 'Timestamp' not in self.raw_message:
            self.debug_messages.append("[Timestamp] not found")
        else:
            self.timestamp = self.raw_message['Timestamp']
        if 'SignatureVersion' not in self.raw_message:
            self.debug_messages.append("[SignatureVersion] not found")
        else:
            self.signature_version = int(self.raw_message['SignatureVersion'])
        if self.signature_version != 1:
            self.debug_messages.append("UNKNOWN [SignatureVersion] found")
        self._raise_errors_if_any()
        if self.validate_signature:
            validation = crypto.Version1(self)
            self.is_valid = validation.validate()

    def _raise_errors_if_any(self):
        if len(self.debug_messages) > 0:
            error_message = "\n".join(self.debug_messages)
            ex = ValueError(message=error_message)
            logger.error(ex)
            raise ex


class SubscriptionConfirmation(BaseNotification):
    """
    ..Example Message::
    {
      "Type" : "SubscriptionConfirmation",
      "MessageId" : "165545c9-2a5c-472c-8df2-7ff2be2b3b1b",
      "Token" : "2336412f37fb687f5d51e6e241d09c805a5a57b30d712f794cc5f6a988666d92768dd60a747ba6f3beb71854e285d6ad02428b09ceece29417f1f02d609c582afbacc99c583a916b9981dd2728f4ae6fdb82efd087cc3b7849e05798d2d2785c03b0879594eeac82c01f235d0e717736",
      "TopicArn" : "arn:aws:sns:us-west-2:123456789012:MyTopic",
      "Message" : "You have chosen to subscribe to the topic arn:aws:sns:us-west-2:123456789012:MyTopic.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
      "SubscribeURL" : "https://sns.us-west-2.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-west-2:123456789012:MyTopic&Token=2336412f37fb687f5d51e6e241d09c805a5a57b30d712f794cc5f6a988666d92768dd60a747ba6f3beb71854e285d6ad02428b09ceece29417f1f02d609c582afbacc99c583a916b9981dd2728f4ae6fdb82efd087cc3b7849e05798d2d2785c03b0879594eeac82c01f235d0e717736",
      "Timestamp" : "2012-04-26T20:45:04.751Z",
      "SignatureVersion" : "1",
      "Signature" : "EXAMPLEpH+DcEwjAPg8O9mY8dReBSwksfg2S7WKQcikcNKWLQjwu6A4VbeS0QHVCkhRS7fUQvi2egU3N858fiTDN6bkkOxYDVrY0Ad8L10Hs3zH81mtnPk5uvvolIC1CXGu43obcgFxeL3khZl8IKvO61GWB6jI9b5+gLPoBc1Q=",
      "SigningCertURL" : "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-f3ecfb7224c7233fe7bb5f59f96de52f.pem"
    }
    """
    SIGNATURE_ATTR = ('Message',
                      'MessageId',
                      'SubscribeURL',
                      'Timestamp',
                      'Token',
                      'TopicArn',
                      'Type')

    def __init__(self, raw_message, validate_signature=True):
        super(SubscriptionConfirmation, self).__init__(raw_message, validate_signature)
        if 'Message' not in self.raw_message:
            self.debug_messages.append("[Message] not found")
        else:
            self.message = self.raw_message['Message']
        if 'Token' not in self.raw_message:
            self.debug_messages.append("[Token] not found")
        else:
            self.token = self.raw_message['Token']
        if 'SubscribeURL' not in self.raw_message:
            self.debug_messages.append("[SubscribeURL] not found")
        else:
            self.subscribe_url = self.raw_message['SubscribeURL']
        self.subscribe()
        self._raise_errors_if_any()

    def subscribe(self):
        """
        Todo: perhaps the addition of a whitelist of topic ARNs in the config
        :return void:
        """
        h = httplib2.Http()
        response, content = h.request(self.raw_message['SubscribeURL'], 'GET')
        return response, content


class Notification(BaseNotification):
    """
    ..Example Message::
    {
      "Type" : "Notification",
      "MessageId" : "22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324",
      "TopicArn" : "arn:aws:sns:us-west-2:123456789012:MyTopic",
      "Subject" : "My First Message",
      "Message" : "Hello world!",
      "Timestamp" : "2012-05-02T00:54:06.655Z",
      "SignatureVersion" : "1",
      "Signature" : "EXAMPLEw6JRNwm1LFQL4ICB0bnXrdB8ClRMTQFGBqwLpGbM78tJ4etTwC5zU7O3tS6tGpey3ejedNdOJ+1fkIp9F2/LmNVKb5aFlYq+9rk9ZiPph5YlLmWsDcyC5T+Sy9/umic5S0UQc2PEtgdpVBahwNOdMW4JPwk0kAJJztnc=",
      "SigningCertURL" : "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-f3ecfb7224c7233fe7bb5f59f96de52f.pem",
      "UnsubscribeURL" : "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:123456789012:MyTopic:c9135db0-26c4-47ec-8998-413945fb5a96"
    }
    """
    SIGNATURE_ATTR = ('Message',
                      'MessageId',
                      'Subject',
                      'Timestamp',
                      'TopicArn',
                      'Type')

    def __init__(self, raw_message, validate_signature=True):
        super(Notification, self).__init__(raw_message, validate_signature)
        if 'Message' not in self.raw_message:
            self.debug_messages.append("[Message] not found")
        else:
            try:
                self.message = json.loads(raw_message['Message'])
            except ValueError:
                pass
            self.message = raw_message['Message']
        self._raise_errors_if_any()


class UnsubscribeConfirmation(BaseNotification):
    """
    ..Example Message::
    """
    SIGNATURE_ATTR = ('Message',
                      'MessageId',
                      'SubscribeURL',
                      'Timestamp',
                      'Token',
                      'TopicArn',
                      'Type')

    def __init__(self, raw_message, validate_signature=True):
        super(UnsubscribeConfirmation, self).__init__(raw_message, validate_signature)
        if 'Message' not in self.raw_message:
            self.debug_messages.append("[Message] not found")
        else:
            self.message = self.raw_message['Message']
        self._raise_errors_if_any()
