import argparse
import json
from pathlib import Path
from vendorchain.stats import summarize_campaign
parser=argparse.ArgumentParser();parser.add_argument('trials');parser.add_argument('--output',required=True)
args=parser.parse_args();rows=[json.loads(l) for l in Path(args.trials).read_text().splitlines() if l.strip()]
Path(args.output).write_text(json.dumps(summarize_campaign(rows),indent=2))
