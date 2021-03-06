#! /usr/bin/python3
'''
    Utilities for managing queues.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from random import uniform
from redis import Redis
from rq.queue import Queue
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile

log = LogFile()

def wait_until_queued(job, secs_to_wait):
    ''' Wait until the job is queued or timeout. '''

    secs = 0
    while (secs < secs_to_wait and
           not job.is_queued and
           not job.is_started and
           not job.is_finished ):
        sleep(1)
        secs += 1

def wait_until_queue_empty(name, port):
    '''
        Wait until the queue is empty.

        >>> from goodcrypto.oce.gpg_queue_settings import GPG_RQ, GPG_REDIS_PORT
        >>> wait_until_queue_empty(GPG_RQ, GPG_REDIS_PORT)
    '''

    redis_connection = Redis(REDIS_HOST, port)
    queue = Queue(name=name, connection=redis_connection)
    while not queue.is_empty():
        # sleep a random amount of time to minimize deadlock
        secs = uniform(1, 20)
        sleep(secs)

def get_job_count(name, port):
    '''
        Get the count of jobs in the queue.

        >>> from goodcrypto.oce.gpg_queue_settings import GPG_RQ, GPG_REDIS_PORT
        >>> wait_until_queue_empty(GPG_RQ, GPG_REDIS_PORT)
        >>> get_job_count(GPG_RQ, GPG_REDIS_PORT)
        0
    '''

    redis_connection = Redis(REDIS_HOST, port)
    queue = Queue(name=name, connection=redis_connection)
    job_ids = list(queue.get_job_ids())
    if len(job_ids) > 0:
        for job_id in job_ids:
            log.write_and_flush('job id: {}'.format(job_id))
    return queue.count

def get_job_results(queue, job, secs_to_wait, purpose):
    ''' Get the initial job results. '''

    if job is None:
        log_message('unable to queue {} job for {}'.format(queue.name, purpose))
    else:
        job_id = job.get_id()

        wait_until_queued(job, secs_to_wait)

        if job.is_failed:
            job_dump = job.to_dict()

            if 'exc_info' in job_dump:
                error = job_dump['exc_info']
                log_message('{} job exc info: {}'.format(job_id, error))
            elif 'status' in job_dump:
                error = job_dump['status']
                log_message('{} job status: {}'.format(job_id, error))
            else:
                log_message('job dump: {}'.format(job_dump))
            job.cancel()
            queue.remove(job_id)


        elif job.is_queued or job.is_started or job.is_finished:
            result_ok = True

        else:
            result_ok = False
            log_message('job with unknown result: {}'.format(job))

    return result_ok

def clear_failed_queue(name, port):
    '''
        Clear all the jobs in the failed queue.

        >>> from goodcrypto.oce.gpg_queue_settings import GPG_RQ, GPG_REDIS_PORT
        >>> clear_failed_queue(GPG_RQ, GPG_REDIS_PORT)
    '''

    redis_connection = Redis(REDIS_HOST, port)
    queue = Queue(name='failed', connection=redis_connection)
    job_ids = list(queue.get_job_ids())
    if len(job_ids) > 0:
        log.write('clearing {} failed jobs'.format(name))
        for job_id in job_ids:
            job = queue.fetch_job(job_id)
            if job is not None:
                job_dump = job.to_dict()
                log.write_and_flush('   {}\n\n'.format(job_dump))
            queue.remove(job_id)

def log_message(message):
    '''
        Log the message.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test message')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.utils.manage_queues.log'))
        True
    '''

    log.write_and_flush(message)


