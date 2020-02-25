import logging
from typing import TYPE_CHECKING, Any, Optional

from alertaclient.api import Client
from flask import request

from alerta.exceptions import ForwardingLoop
from alerta.plugins import PluginBase
from alerta.utils.response import absolute_url

if TYPE_CHECKING:
    from alerta.models.alert import Alert  # noqa


LOG = logging.getLogger('alerta.plugins.forwarder')

X_LOOP_HEADER = 'X-Alerta-Loop'


def http_origin():
    return absolute_url()


def append_to_header(origin):
    x_loop = request.headers.get(X_LOOP_HEADER)
    return origin if not x_loop else '{},{}'.format(x_loop, origin)


def is_in_xloop(server):
    x_loop = request.headers.get(X_LOOP_HEADER, '')
    return server in x_loop


class Forwarder(PluginBase):
    """
    Alert and action forwarder for federated Alerta deployments
    See https://docs.alerta.io
    """

    def pre_receive(self, alert: 'Alert', **kwargs) -> 'Alert':
        # guard against forwarding loops
        if is_in_xloop(http_origin()):
            raise ForwardingLoop('Alert {} already processed by {}. Ignoring.'.format(alert.id, http_origin()))
        return alert

    def post_receive(self, alert: 'Alert', **kwargs) -> Optional['Alert']:

        print('post-receive: forward alert to remotes...')

        origin = http_origin()
        x_loop = request.headers.get(X_LOOP_HEADER, '')

        for remote, auth, actions in self.get_config('FWD_DESTINATIONS', default=[], type=list, **kwargs):

            if remote in x_loop:
                print('post-receive: {} is in xloop already. do not forward back to remote.'.format(remote))
                continue

            if not ('*' in actions or 'fwd' in actions):
                print('post-receive: alert forwarding not configured.')
                continue

            print('post-receive: forward alert to {}...'.format(remote))

            headers = {X_LOOP_HEADER: append_to_header(origin)}
            client = Client(endpoint=remote, **auth, headers=headers)

            try:
                _, _, message = client.send_alert(**alert.get_body())
            except Exception as e:
                LOG.warning('Failed to forward alert to {} - {}'.format(remote, str(e)))
                continue

            if message:
                print('post-receive: {} - {}'.format(alert.id, message))
            else:
                print('post-receive: {} - success!'.format(alert.id))

            print('post-receive: sent!')

        print('post-receive: continue to process alert...')

        return alert

    def status_change(self, alert: 'Alert', status: str, text: str, **kwargs) -> Any:
        return

    def take_action(self, alert: 'Alert', action: str, text: str, **kwargs) -> Any:

        print('take-action: start...')

        # guard against forwarding loops
        origin = http_origin()
        x_loop = request.headers.get(X_LOOP_HEADER, '')

        if origin in x_loop:
            print('take-action : loop detected.')
            raise ForwardingLoop('Alert {} action {} already processed by {}.'.format(alert.id, action, origin))

        print('take-action: forward alert action to remotes...')

        for remote, auth, actions in self.get_config('FWD_DESTINATIONS', default=[], type=list, **kwargs):

            if remote in x_loop:
                print('take-action: remote {} is in xloop. do not forward action.'.format(remote))
                continue

            if not ('*' in actions or 'actions' in actions or action in actions):
                print('take-action: alert action forwarding forbidden.')
                continue

            print('take-action: trigger alert action {} on remote {}...'.format(action, remote))

            headers = {X_LOOP_HEADER: append_to_header(origin)}
            client = Client(endpoint=remote, **auth, headers=headers)

            try:
                message = client.action(alert.id, action, text)
            except Exception as e:
                LOG.warning('Failed to forward action to {} - {}'.format(remote, str(e)))
                continue

            print('take-action: {} ; {} - {}'.format(alert.id, action, message))

            print('take-action: sent!')

        print('take-action: continue to process action...')

        return alert

    def delete(self, alert: 'Alert', **kwargs) -> bool:

        print(request.environ)
        print('delete: start...')

        # guard against forwarding loops
        origin = http_origin()
        x_loop = request.headers.get(X_LOOP_HEADER, '')

        if origin in x_loop:
            print('delete : loop detected.')
            raise ForwardingLoop('Alert {} already deleted by {}.'.format(alert.id, origin))

        print('delete: forward alert delete to remotes...')

        for remote, auth, actions in self.get_config('FWD_DESTINATIONS', default=[], type=list, **kwargs):

            if remote in x_loop:
                print('delete: remote {} is in xloop. do not forward delete.'.format(remote))
                continue

            if not ('*' in actions or 'actions' in actions or 'delete' in actions):
                print('delete: alert delete forwarding forbidden.')
                continue

            print('delete: trigger delete on remote {}...'.format(remote))

            headers = {X_LOOP_HEADER: append_to_header(origin)}
            client = Client(endpoint=remote, **auth, headers=headers)

            try:
                message = client.delete_alert(alert.id)
            except Exception as e:
                LOG.warning('Failed to forward delete to {} - {}'.format(remote, str(e)))
                continue

            print('delete: {} ; {}'.format(alert.id, message))

            print('delete: sent!')

        print('delete: continue to process delete...')

        return True  # always continue with local delete even if remote delete(s) fail
