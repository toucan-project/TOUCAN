from time import sleep
from threading import Thread, Lock
from os import mkfifo, access, R_OK

from canary_api import settings

from canary_utils.lib import logger
from canary_utils.lib.log import Log, Nginx, SMB, DNS


class serverState(object):
    """Maintains server state, stops the server when disabled."""

    def __init__(self):
        """Initialize lock."""

        self.lock = Lock()
        self.active = False

    def is_active(self):
        """Maintains the current state of the server."""

        with self.lock:
            if self.active:
                return True

            else:
                return False


class cmdServer():
    """Runs the cmdServer as a daemon."""

    def __init__(self):
        """Initialize server state and start logger and parsers.."""

        self.state = serverState()

        with self.state.lock:
            self.state.active = True

        self.logger = logger.Logger()

        if not access(settings.PIPE, R_OK):
            mkfifo(settings.PIPE)

        self.start_parsers()

    def start_parsers(self):
        """Starts the log parsers based on the list in the configuration."""

        try:
            for parser in settings.parsers:
                index = settings.parsers.index(parser)

                settings.parsers[index].append(Thread(target=self.start_log,
                                             args=(parser[0],)))
                settings.parsers[index][1].setDaemon(True)
                settings.parsers[index][1].start()

            watch = Thread(target=self.watch_threads, args=())
            watch.setDaemon(True)
            watch.start()

            self.logger.log_info('daemons started successfully')

            while self.state.is_active():
                sleep(1)

            self.logger.log_info('shutting down!')

        except Exception as msg:

            if isinstance(msg, FileNotFoundError):

                with self.state.lock:
                    self.state.active = False

            self.logger.log_exception(msg)

    def watch_threads(self):
        """Watchdog to restart potentially crashed threads."""

        while self.state.is_active:
            self.check_alive()
            sleep(3)

    def check_alive(self):
        """Check to see whether the thread is still alive."""

        for thread in settings.parsers:
            if not thread[1].is_alive():

                self.restart_thread(thread)
                self.logger.log_info(f"Restarted thread {str(thread[0])}")

    def restart_thread(self, thread):
        """Reinitialize threads, as restarting is not possible."""

        thread[1] = Thread(target=self.start_log,
                           args=(thread[0],))
        thread[1].setDaemon(True)
        thread[1].start()

    def start_log(self, log_type):
        """Start log parsers for detecting canaries."""

        try:
            self.logd = Log()

            if log_type == 'smb':
                self.parser = SMB()

            elif log_type == 'nginx':
                self.parser = Nginx()

            elif log_type == 'dns':
                self.parser = DNS()

            self.logd.monitor_log(self.parser.parse,
                                  settings.log[log_type],
                                  self.state)

        except Exception as msg:
            self.logger.log_exception(msg)

    def stop_parsers(self):

        self.logger.log_info('stopping parsers...')

        with self.state.lock:
            self.state.active = False

            for thread in settings.parsers:

                if len(thread) > 1:

                    if thread[1].is_alive():
                        thread[1].join(5)

        self.logger.log_info('parsers stopped!')
