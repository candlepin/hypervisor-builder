import contextlib
import os
import socket

import paramiko

from hypervisor import FailException, logger


class SSHConnect:
    """Extended SSHClient allowing custom methods"""

    def __init__(self, host, user, pwd=None, rsafile=None, port=22, timeout=1800):
        """
        :param str host: The hostname or ip of the server to establish connection.
        :param str user: The username to use when connecting.
        :param str pwd: The password to use when connecting.
        :param str rsafile: The path of the ssh private key to use when connecting to the server
        :param int port: The server port to connect to, the default port is 22.
        :param int timeout: Time to wait for the ssh command to finish.
        """
        self.host = host
        self.user = user
        self.pwd = pwd
        self.rsa = rsafile
        self.port = port
        self.timeout = timeout
        self.err = "passwd, rsafile, or ssh-agent must be available"
        self._ssh = None

    def _connect(self):
        """SSH command execution connection with pooling.
        Reuses an existing connection while its transport is still
        active, avoiding the overhead of a new TCP+SSH handshake per
        command. Paramiko channels are independent, so consecutive
        exec_command calls share one transport safely.
        """
        if self._ssh is not None:
            transport = self._ssh.get_transport()
            if transport is not None and transport.is_active():
                return self._ssh
            # Dead transport: close the socket instead of just
            # dropping the reference.
            self.close()
        if self.pwd:
            self._ssh = self.pwd_connect()
        elif self.rsa:
            self._ssh = self.rsa_connect()
        else:
            # Try to use keys from SSH AutoAgent
            self._ssh = self.pwd_connect()
        return self._ssh

    def close(self):
        """Explicitly close the pooled connection."""
        if self._ssh is not None:
            with contextlib.suppress(OSError):
                self._ssh.close()
            self._ssh = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _transfer(self):
        """Sftp download/upload execution connection"""
        if self.pwd:
            return self.pwd_transfer()
        elif self.rsa:
            return self.rsa_transfer()
        else:
            # Try to use keys from SSH AutoAgent
            return self.pwd_transfer()

    def pwd_connect(self):
        """SSH command execution connection by password"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if self.pwd:
            ssh.connect(self.host, self.port, self.user, self.pwd, timeout=self.timeout)
        else:
            logger.info("ssh connect will try to use ssh-agent")
            ssh.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                timeout=self.timeout,
                allow_agent=True,
            )
        return ssh

    def rsa_connect(self):
        """SSH command execution connection by key file"""
        pkey = paramiko.RSAKey.from_private_key_file(self.rsa)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host, self.port, self.user, pkey=pkey, timeout=self.timeout)
        return ssh

    def pwd_transfer(self):
        """Sftp download/upload execution connection by password"""
        if self.pwd:
            transport = paramiko.Transport(self.host, self.port)
            transport.connect(username=self.user, password=self.pwd)
        else:
            logger.info("ssh transfer will try to use ssh-agent")
            transport = paramiko.Transport((self.host, self.port))
            transport.connect(username=self.user, allow_agent=True)
        sftp = paramiko.SFTPClient.from_transport(transport)
        return sftp, transport

    def rsa_transfer(self):
        """Sftp download/upload execution connection by key file"""
        pkey = paramiko.RSAKey.from_private_key_file(self.rsa)
        transport = paramiko.Transport(self.host, self.port)
        transport.connect(username=self.user, pkey=pkey)
        sftp = paramiko.SFTPClient.from_transport(transport)
        return sftp, transport

    def runcmd(self, cmd, if_stdout=False, timeout=None, input_text=None):
        """Executes SSH command on remote hostname.
        :param str cmd: The command to run
        :param str if_stdout: default to return the stderr
        :param int timeout: time in seconds to wait for the command to
            finish (default: None for no timeout)
        :param str input_text: text written to the remote command's
            stdin (default: None for no input). Pass untrusted values
            here instead of interpolating them into the command string.
        :return: the exit code and the decoded output of the command
        """
        ssh = self._connect()
        logger.info(f">>> {cmd}")
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        except (EOFError, OSError, paramiko.SSHException):
            # The pooled transport dropped before the command could
            # start: close the dead connection, reconnect once and
            # start the command again.
            self.close()
            ssh = self._connect()
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        try:
            if input_text is not None:
                stdin.write(input_text)
                stdin.flush()
            # Close the write side so a remote command reading stdin
            # sees EOF instead of hanging.
            stdin.channel.shutdown_write()
        except (EOFError, OSError, paramiko.SSHException):
            # The command may already be running remotely: starting it
            # again could double-execute a non-idempotent command, so
            # do not retry. Drop the dead connection (the next call
            # reconnects) and let the failure propagate.
            self.close()
            raise

        if timeout is not None:
            stdout.channel.settimeout(timeout)

        try:
            # Bound the exit-status wait itself: recv_exit_status()
            # is an unbounded status_event.wait() that the channel
            # timeout does not cover, so a hung remote command would
            # block forever. False means the status never arrived --
            # take the shared timeout path below.
            if timeout is not None and not stdout.channel.status_event.wait(timeout):
                raise TimeoutError()
            code = stdout.channel.recv_exit_status()
            stdout, stderr = stdout.read(), stderr.read()
        except (TimeoutError, socket.timeout):  # noqa: UP041
            # socket.timeout is a distinct class from TimeoutError on
            # Python < 3.10: catching only the latter let a channel
            # timeout surface as a raw traceback there. (UP041 wants
            # the alias dropped -- it only IS an alias on 3.10+, and
            # consumers run older Pythons.)
            logger.error(f"Command execution timed out after {timeout} seconds: {cmd}")
            self.close()
            raise FailException(
                f"Command timed out after {timeout} seconds: {cmd}"
            ) from None

        if if_stdout or not stderr:
            logger.info(f"<<< stdout\n{stdout.decode()}")
            return code, stdout.decode()
        else:
            logger.info(f"<<< stderr\n{stderr.decode()}")
            return code, stderr.decode()

    def get_file(self, remote_file, local_file):
        """Download a remote file to the local machine."""
        sftp, conn = self._transfer()
        sftp.get(remote_file, local_file)
        conn.close()

    def put_file(self, local_file, remote_file):
        """Upload a local file to a remote machine
        :param local_file: either a file path or a file-like object to be uploaded.
        :param remote_file: a remote file path where the uploaded file will be placed.
        """
        sftp, conn = self._transfer()
        sftp.put(local_file, remote_file)
        conn.close()

    def remove_file(self, remote_file):
        """Remove the file at the given path.
        :param remote_file: a remote file path to remove
        """
        sftp, conn = self._transfer()
        sftp.remove(remote_file)
        conn.close()

    def put_dir(self, local_dir, remote_dir):
        """Upload all files from directory to a remote directory
        :param local_dir: all files from local path to be uploaded.
        :param remote_dir: a remote path where the uploaded files will be placed.
        """
        sftp, conn = self._transfer()
        for root, dirs, files in os.walk(local_dir):
            for filespath in files:
                local_file = os.path.join(root, filespath)
                a = local_file.replace(local_dir, "")
                remote_file = os.path.join(remote_dir, a)
                try:
                    sftp.put(local_file, remote_file)
                except Exception:
                    sftp.mkdir(os.path.split(remote_file)[0])
                    sftp.put(local_file, remote_file)
            for name in dirs:
                local_path = os.path.join(root, name)
                a = local_path.replace(local_dir, "")
                remote_path = os.path.join(remote_dir, a)
                try:
                    sftp.mkdir(remote_path)
                except Exception as e:
                    logger.info(e)
        conn.close()
