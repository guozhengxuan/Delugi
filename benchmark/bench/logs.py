"""Narwhal-style log summaries over verified, identity-based campaign evidence.

The remote runners download raw node journals/stdout/stderr before returning.
This parser reads those retained results, checks their frozen hashes and uses
origin-local latency endpoints. It never substitutes missing latency with zero.
"""
from __future__ import annotations
import csv
import hashlib
import json
from pathlib import Path
import tarfile
from .config import read
import campaign_execute


class ParseError(ValueError):
    pass


class LogParser:
    def __init__(self, directory):
        self.directory=Path(directory).resolve()
        self.state=read(self.directory/'state.json')
        self.plan=read(self.directory/'plan.json')
        if self.state['identity']['plan_sha256']!=self.plan['plan_sha256']:
            raise ParseError('logs and campaign plan differ')
        self.rows=[]
        for record in self.state['rows']:
            row={k:record.get(k) for k in ('trial_id','protocol','nodes','case','rate','status','error')}
            resolved_path=self.directory/'resolved'/(record['trial_id']+'.json')
            resolved=read(resolved_path) if resolved_path.is_file() else None
            row['duration_s']=(resolved or {}).get('effective',{}).get('duration',self.plan['config']['duration'])['measure_s']
            row['useful_transaction_bytes']=self.plan['config']['useful_transaction_bytes']
            row['faults']=0 if row['case']=='healthy' else len((resolved or {}).get('effective',{}).get('faulty_identities',[0]))
            binding=record.get('result')
            if binding:
                path=self.directory/'trials'/record['trial_id']/'result.json'
                if not path.is_file() or path.is_symlink():raise ParseError('result file absent or linked')
                with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
                if digest!=binding['sha256']:raise ParseError('frozen trial result changed')
                result=read(path)
                metrics=campaign_execute.metrics(result,row['protocol'])
                if metrics!=record.get('metrics'):raise ParseError('summary metrics differ from retained trial evidence')
                row.update(metrics or {})
                reduced=result.get('reduction',result);cohort=reduced.get('cohort',{})
                if cohort:
                    row['endpoint_contract']=cohort['endpoint_contract']
                    for key,label in [('scheduled_to_output','end_to_end'),('admission_to_output','admission')]:
                        endpoint=cohort[key]
                        for q in ('p50','p95','p99'):
                            row[label+'_'+q+'_ms']=endpoint[q]['value_ms']
                            row[label+'_'+q+'_lower_bound_ms']=endpoint[q]['lower_bound_ms']
                            row[label+'_'+q+'_status']=endpoint[q]['status']
                    row['measurement_completion_count']=cohort['window']['completion_count']
                    row['cohort_completion_fraction']=cohort['completed']/cohort['scheduled'] if cohort['scheduled'] else None
                row['result_sha256']=digest
            elif row['status'] in ('passed','completed'):
                raise ParseError('successful trial is missing its bound result')
            self.rows.append(row)
        expected={t['id'] for t in self.plan['trials']}
        if len({r['trial_id'] for r in self.rows})!=len(self.rows) or any(r['trial_id'] not in expected for r in self.rows):
            raise ParseError('duplicate or unplanned trial in logs')

    @classmethod
    def process(cls,directory):return cls(directory)

    def result(self):
        lines=['Protocol       Case                  Status       Input      Goodput   p50 end-to-end   Completed']
        for r in self.rows:
            number=lambda v: 'n/a' if v is None else f'{v:.2f}'
            latency=number(r.get('end_to_end_p50_ms'))
            if r.get('end_to_end_p50_status')=='censored':latency='>='+number(r.get('end_to_end_p50_lower_bound_ms'))
            lines.append(f"{r['protocol']:<14} {r['case']:<21} {r['status']:<12} {str(r['rate']):>5} tx/s {number(r.get('goodput_tps')):>7}  {latency:>10} ms  {r.get('completed','?')}/{r.get('scheduled','?')}")
        lines+=['Goodput: exact useful completions inside the measurement window.',
                'End-to-end: intended arrival to origin-local payload-verified contiguous output; cohort observed through drain.',
                'Censored latency is a lower bound. One run is not a confidence interval.']
        return '\n'.join(lines)

    def export(self, output=None):
        output=Path(output or self.directory/'logs');output.mkdir(parents=True,exist_ok=True)
        fields=list(dict.fromkeys(k for r in self.rows for k in r))
        with (output/'summary.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(self.rows)
        (output/'summary.txt').write_text(self.result()+'\n')
        data={'schema':1,'plan_sha256':self.plan['plan_sha256'],'status':self.state['status'],
              'rows':self.rows,'source':'hash-checked trial results and retained per-replica journals',
              'measurement_duration_s':self.plan['config']['duration']['measure_s'],
              'drain_s':self.plan['config']['duration']['drain_s']}
        (output/'summary.json').write_text(json.dumps(data,indent=2,allow_nan=False)+'\n')
        return {'directory':str(output),'csv':str(output/'summary.csv'),'summary':str(output/'summary.json'),'text':self.result()}

    def download(self, destination=None):
        """Bundle already-downloaded logs; no extra workload or remote execution."""
        destination=Path(destination or self.directory/'downloaded-logs.tar.gz').resolve()
        if destination.exists():raise ParseError('choose a new log archive destination')
        ignored={'artifact','shared-build','snapshot','specification','keys','private-keys','.plot-cache'}
        allowed={'.json','.jsonl','.log','.stdout','.stderr','.txt','.csv','.sqlite','.db'}
        selected=[];total=0
        for path in sorted(self.directory.rglob('*')):
            if path.is_symlink():continue
            if not path.is_file() or path.suffix not in allowed or ignored.intersection(path.relative_to(self.directory).parts):continue
            if path.name.startswith(('key-','secret-')) or path.name=='private.key':continue
            total+=path.stat().st_size
            if total>2*1024**3:raise ParseError('log archive exceeds 2GiB; raw files remain retained')
            selected.append(path)
        destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        temporary=destination.with_name(destination.name+'.pending')
        try:
            with temporary.open('xb') as stream:
                temporary.chmod(0o600)
                with tarfile.open(fileobj=stream,mode='w:gz') as archive:
                    for path in selected:archive.add(path,arcname=path.relative_to(self.directory),recursive=False)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        with destination.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        return {'archive':str(destination),'sha256':digest,'files':len(selected),'uncompressed_bytes':total,
                'scope':'downloaded per-replica logs/results; build snapshots and private key directories excluded'}
