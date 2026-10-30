"""Trial, not request, is the unit of statistical replication."""
import math
import statistics
from scipy.stats import t

def summarize(values):
    if not values or any(not isinstance(x,(float,int)) or not math.isfinite(x) for x in values):
        raise ValueError('finite measurements are required; missing values cannot be silently dropped')
    n=len(values);mean=statistics.mean(values)
    sd=statistics.stdev(values) if n>1 else None
    half=float(t.ppf(.975,n-1))*sd/math.sqrt(n) if n>1 else None
    return {'n':n,'mean':mean,'stddev':sd,'ci95':None if half is None else [mean-half,mean+half],
            'publicationNMet':n>=50,'unit':'independent trial mean','method':'two-sided Student t'}

def summarize_campaign(rows):
    groups={}
    for row in rows:
        if row.get('warmup'):
            continue
        groups.setdefault(row['concurrency'],[]).append(row)
    result={}
    for concurrency,trials in groups.items():
        complete=[r for r in trials if r.get('trialMeanMs') is not None]
        failures=sum(r.get('failed',0) for r in trials)
        result[str(concurrency)]={
            'trialLatencyMs':summarize([r['trialMeanMs'] for r in complete]) if complete else None,
            'successfulThroughputPerSecond':summarize([r['successful']/r['durationSeconds'] for r in trials]),
            'offered':sum(r['offered'] for r in trials),'failed':failures,
            'trialsWithoutSuccessfulCommits':len(trials)-len(complete),
            'qualifiedForPaper':False,
            'protocolMinimumMet':len(trials)>=50 and len(complete)==len(trials) and all(r.get('evidence')=='fabric-commit-confirmed' for r in trials),
            'notes':'Latency uses successful commits within each trial. All failed attempts and empty trials remain visible. Independence and cluster metadata must be reviewed separately.'}
    return result
