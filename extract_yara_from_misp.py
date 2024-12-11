#!/usr/bin/env python3
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/eti/
#
# Author: ESET Research
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2024 ESET
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import sys
import argparse
from typing import Union
try:
    from pymisp import MISPEvent, PyMISP, MISPObject, MISPGalaxy, MISPAttribute
except ModuleNotFoundError:
    print("[-] PyMISP module is not installed.")

MISP_URL: str = "MISP_INSTANCE_URL"
MISP_API_KEY: str = "YOUR_API_KEY"

ESET_THREAT_ACTOR_GALAXY_UUID = "b9e6761a-d501-4cac-94da-8e75e5d26ddb"


class MispYaraDumper:
    def __init__(self) -> None:
        if MISP_API_KEY == "YOUR_API_KEY":
            sys.exit("[-] MISP API KEY is missing")
        if MISP_URL == "MISP_INSTANCE_URL":
            sys.exit("[-] MISP URL is missing")
        self.misp: PyMISP = PyMISP(MISP_URL, MISP_API_KEY)

    def get_event_by_id(self, event_id: int) -> Union[MISPEvent, None]:
        event: MISPEvent = self.misp.get_event(event_id, pythonify=True)
        if not isinstance(event, MISPEvent):
            sys.exit(f"[!] No MISP event found with ID: {event_id} ")
        return event

    def dump_all_yaras_from_TA_AS(self) -> None:
        events: list[MISPEvent] = self.get_TA_AS()
        for event in events:
            self.dump_yaras_from_event(event)

    def get_TA_AS(self) -> list[MISPEvent]:
        return self.misp.search(
            tags=["Activity Summary", "Technical Analysis"],
            published=True,
            pythonify=True
        )

    def dump_yaras_from_event_id(self, event_id: int) -> None:
        event: MISPEvent = self.get_event_by_id(event_id)
        self.dump_yaras_from_event(event)

    def dump_yaras_from_event(self, event: MISPEvent) -> None:
        objects: list[MISPObject] = event.get_objects_by_name("yara")
        if not objects:
            print("[+] No Yara rules found in event {}".format(event.id))
            return
        for obj in objects:
            yara_name_attributes: list[MISPAttribute] = obj.get_attributes_by_relation("yara-rule-name")
            yara_rule_attributes: list[MISPAttribute] = obj.get_attributes_by_relation("yara")
            for y_name_attr in yara_name_attributes:
                yara_name: str = y_name_attr.value
            for y_rule_attr in yara_rule_attributes:
                yara_rule: str = y_rule_attr.value
            if yara_rule and yara_name:
                print("[+] Extracting {}.yar from {}".format(yara_name, event.info))
                with open(yara_name + ".yar", "w") as rule_file:
                    rule_file.write(yara_rule)
        return

    def dump_yaras_from_threat_actor(self, threat_actor: str) -> None:
        threat_actor_tag_name = self.get_eset_threat_actor_tag_name(threat_actor)
        if threat_actor_tag_name is not None:
            events: list[MISPEvent] = self.misp.search(tag=[threat_actor_tag_name], pythonify=True)
            for event in events:
                self.dump_yaras_from_event(event)
        else:
            print("[!] No MISP event found for ESET Threat Actor: {}".format(threat_actor))

    def get_eset_threat_actor_tag_name(self, threat_actor: str) -> str:
        galaxy: MISPGalaxy = self.misp.get_galaxy(
            ESET_THREAT_ACTOR_GALAXY_UUID,
            withCluster=True,
            pythonify=True
        )
        threat_actor_tag_name = None
        for cluster in galaxy.clusters:
            if cluster.value.lower() == threat_actor.lower():
                threat_actor_tag_name = cluster.tag_name
                break
        return threat_actor_tag_name


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--event", help="event ID from which to extract yara rules", type=int)
    parser.add_argument("-g", "--group", help="group name from which to extract yara rules", type=str)
    parser.add_argument("-a", "--all", help="extract all yara rules", action="store_true")

    args = parser.parse_args()

    yara_dumper = MispYaraDumper()
    if args.event:
        if args.event == 0:
            sys.exit("[-] Event ID 0 does not exist.")
        yara_dumper.dump_yaras_from_event_id(args.event)
    if args.group:
        yara_dumper.dump_yaras_from_threat_actor(args.group)
    if args.all:
        print("[+] Extracting all yara rules from every TA and AS, this will take a few minutes.")
        yara_dumper.dump_all_yaras_from_TA_AS()
    return

if __name__ == "__main__":
    main()
