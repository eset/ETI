# ETI scripts
Collection of scripts to interact with ESET MISP instance.

## YARA extractor
[Script](./extract_yara_from_misp.py) to extract yara rules from MISP for a given event or ESET Threat Actor.

Usage:  
`python extract_yara_from_misp.py -e EVENT_ID`  
`python extract_yara_from_misp.py -g "GROUP NAME"`  
`python extract_yara_from_misp.py -a` (extracts all yara rules)