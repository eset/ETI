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
# Copyright (C) 2025 ESET
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


import argparse
import sys
from typing import Union
try:
    from pymisp import MISPEvent, PyMISP, MISPGalaxy, MISPGalaxyCluster
except ModuleNotFoundError:
    print("[-] PyMISP module is not installed.")

MISP_URL: str = "MISP_INSTANCE_URL"
MISP_API_KEY: str = "YOUR_API_KEY"

ESET_THREAT_ACTOR_GALAXY_UUID = "b9e6761a-d501-4cac-94da-8e75e5d26ddb"


class MISPThreatActorRegionDumper:
    def __init__(self) -> None:
        if MISP_API_KEY == "YOUR_API_KEY":
            sys.exit("[-] MISP API KEY is missing")
        if MISP_URL == "MISP_INSTANCE_URL":
            sys.exit("[-] MISP URL is missing")
        self.misp: PyMISP = PyMISP(MISP_URL, MISP_API_KEY, ssl=False)

    def get_event_by_id(self, event_id: int) -> Union[MISPEvent, None]:
        """Retrieve MISP event.
        """
        event: MISPEvent = self.misp.get_event(event_id, pythonify=True)
        if not isinstance(event, MISPEvent):
            sys.exit(f"[!] No MISP event found with ID: {event_id} ")
        return event

    def get_cluster_from_event_id(self, event_id: int) -> None:
        """Retrieve Threat Actors' region(s) for a given MISP Event ID.
        """
        regions: set(str) = set()
        event: MISPEvent = self.get_event_by_id(event_id)
        galaxies: list[MISPGalaxy] = event.Galaxy
        for galaxy in galaxies:
            if galaxy.uuid == ESET_THREAT_ACTOR_GALAXY_UUID:
                for cluster in galaxy.clusters:
                    region = self.get_cluster_region(cluster)
                    if region:
                        regions.add(region)
        if len(regions):
            # The MISP Event has one Threat Actor.
            print(f"[+] Threat Actor region is {regions.pop()} for MISP event {event.info}.")
        else:
            # The MISP Event has multiple Threat Actors.
            for region in regions:
                print(f"[+] Threat Actors' regions are {''.join(i for i in region[0])} for MISP event {event.info}.")

    def get_cluster_region(self, cluster: MISPGalaxyCluster) -> str:
        """Retrieve, if exist, the country of the Threat Actor."""
        if cluster.meta:
            countries = cluster.meta.get("country", [])
            if len(countries):
                return countries.pop()
            elif len(countries) > 1:
                print("[-] Multiple regions found for the same Threat Actor cluster.")
            else:
                print(f"[+] No region found for cluster {cluster.value}")
            return ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-e",
        "--event",
        help="event ID from which to retrieve Threat Actor's region",
        type=int
    )

    args = parser.parse_args()

    if args.event:
        if args.event == 0:
            sys.exit("[-] Event ID 0 does not exist.")
        dumper = MISPThreatActorRegionDumper()
        dumper.get_cluster_from_event_id(args.event)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return

if __name__ == "__main__":
    """Retrieve Threat Actor's region based on a given MISP event."""
    main()
