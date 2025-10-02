Table of Contents
=================

* [ETI scripts](#eti-scripts)
   * [YARA extractor](#yara-extractor)
   * [Threat Actor's Region extractor](#threat-actors-region-extractor)
   * [Examples of common queries](#examples-of-common-queries)

## ETI scripts
Collection of scripts to interact with ESET MISP instance.

### YARA extractor
[Script](./extract_yara_from_misp.py) to extract yara rules from MISP for a given event or ESET Threat Actor.

Usage:  
`python extract_yara_from_misp.py -e EVENT_ID`  
`python extract_yara_from_misp.py -g "GROUP NAME"`  
`python extract_yara_from_misp.py -a` (extracts all yara rules)

### Threat Actor's Region extractor
[Script](./extract_threat_actor_country.py) to extract Threat Actor's region
from MISP for a given event.

Usage:
`python extract_threat_actor_country.py -e EVENT_ID`

### Examples of common queries

[Examples.ipynb](./Examples.ipynb) is a Jupyter Notebook (https://jupyter.org)
is inspired from PyMISP doc and examples
(https://github.com/MISP/PyMISP/tree/main/examples) and contains the whole
setup and few queries allowing to start playing with ESET MISP instance.
