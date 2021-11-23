#!/usr/bin/env python3
import os
import frida
import glob
import time
import json

from frida_tools.application import ConsoleApplication


PWD = os.path.dirname(os.path.abspath(__file__))

class Application(ConsoleApplication):

    SESSION_ID_LENGTH = 32
    MASTER_KEY_LENGTH = 48

    def _add_options(self, parser):
        parser.add_option('-o', '--output', help='The output directory')

    def _initialize(self, parser, options, args):
        if not os.path.exists(options.output):
            os.makedirs(options.output)
        self._output_dir = options.output

    def _usage(self):
        return 'usage: %prog [options] target'

    def _needs_target(self):
        return True

    @staticmethod
    def _agent():
        js_files = glob.glob(f'{PWD}/scripts/*.js', recursive=True)
        js_script = ''
        for js_file in js_files:
            with open(js_file, mode='r') as f:
                js_script += f.read()
        with open(f'{PWD}/script.txt', mode='w') as f:
            f.write(js_script)
        return js_script
        
    def _start(self):
        self._output_files = {}
        self._update_status('Attached')

        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._session_cache = set()

        self._script = self._session.create_script(self._agent())
        self._script.on('message', on_message)

        self._update_status('Loading script...')
        self._script.load()
        self._update_status('Loaded script')
        api = self._script.exports
        api.log_ssl_keys()
        api.log_aes_info()
        self._update_status('Loaded script')
        self._resume()
        time.sleep(1)
        # api.log_device_info()

    def _on_child_added(self, child):
        print('⚡ child_added: {}'.format(child))
        self._instrument(child.pid)

    def _on_child_removed(self, child):
        print('⚡ child_removed: {}'.format(child))

    def _save_data(self):
        for filename, elt in self._output_files.items():
            if len(elt) == 0:
                continue
            data_type = elt[0].get('data_type')
            with open(f'{self._output_dir}/{filename}', mode='w') as out:
                if data_type == 'json':
                    json.dump(elt, out, indent=2)
                else:
                    for record in elt:
                        data = record.get('data')
                        out.write(f'{data}\n')


    def _acc_data(self, data):
        output_file = data.get('dump')
        if output_file not in self._output_files:
            self._output_files[output_file] = []
        self._output_files[output_file].append(data)

    def _on_message(self, message, data):
        if message['type'] == 'send':
            if message.get('payload'):
                self._acc_data(message.get('payload'))
                return

def main():
    try:
        app = Application()
        app.run()
    except KeyboardInterrupt as k:
        # Have to handle something?
        pass
    finally:
        app._save_data()


if __name__ == '__main__':
    main()


