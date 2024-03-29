#!/usr/bin/env python3
# CI Test script: generate all queries with netwitness backend.
# Copyright 2018 John Tuckner 

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import functools
import sys
import pprint
pp = pprint.PrettyPrinter()

# Configuration
index = "test"
threatcodec_cmd = "tools/threatcodec"
threatcodec_processing_prefix = "* Processing Threatcode input "

queries = asyncio.Queue()

# threatcodec runner coroutinne
async def run_threatcodec():
    threatcodec = asyncio.create_subprocess_exec(
            threatcodec_cmd, "-t", "netwitness", "-v", "-I", "-r", "rules/",
            stdout=asyncio.subprocess.PIPE,
            )
    print("* Launching threatcodec")
    proc = await threatcodec
    print("* threatcodec launched with PID {}".format(proc.pid))

    cur_rule = None
    while True:
        line = await proc.stdout.readline()
        if not line:
            print("* threatcodec finished")
            await queries.put((None, None))
            break
        else:
            strline = str(line, 'utf-8').rstrip()
            if strline.startswith(threatcodec_processing_prefix):
                cur_rule = strline[len(threatcodec_processing_prefix):]
            else:
                await queries.put((cur_rule, strline))
    await proc.wait()

    exitcode = proc.returncode
    print("* threatcodec returned with exit code {}".format(exitcode))
    return exitcode

task_threatcodec = asyncio.ensure_future(run_threatcodec())
tasks = [
        task_threatcodec
        ]

loop = asyncio.get_event_loop()
done, pending = loop.run_until_complete(asyncio.wait(tasks))
loop.close()
print()

# Check if threatcodec runned successfully
try:
    if task_threatcodec.result() != 0:       # threatcodec failed
        print("!!! threatcodec failed while test!")
        sys.exit(1)
except Exception as e:
    print("!!! threatcodec failed while test!")
    sys.exit(2)
