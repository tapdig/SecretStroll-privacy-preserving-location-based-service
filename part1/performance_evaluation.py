import sys
import time
import argparse
import numpy as np
import pandas as pd
import jsonpickle
import matplotlib.pyplot as plt
import json
import os
import random
from tqdm import tqdm

from stroll import Server, Client
import credential

# setup arguments
parser = argparse.ArgumentParser(description='ABC Performance Evaluation')
parser.add_argument('--trials', type=int, default=30, 
                    help='Number of trials to run per subscription attributes count (default: 30)')
parser.add_argument('--output-dir', type=str, default='evaluation_results', 
                    help='Directory to save results (default: evaluation_results)')
args = parser.parse_args()

os.makedirs(args.output_dir, exist_ok=True)

N_TRIALS = args.trials
SUBSCRIPTION_COUNTS = [1, 3, 5, 10]  # number of subscription attributes

# some subscription types
SUBSCRIPTION_TYPES = [
    'bar', 'supermarket', 'club', 'restaurant', 'gym', 'dojo', 
    'museum', 'cafeteria', 'appartment_block', 'office', 'villa', 
    'company', 'laboratory'
]

def create_subscriptions(subscription_count):
    """Create subscriptions from subscription types to evaluate different number of attributes"""
    if subscription_count <= 0:
        return []
    available_subs = SUBSCRIPTION_TYPES.copy()
    random.shuffle(available_subs)  # randomly pick from subscription types 
    return available_subs[:subscription_count]

def precise_timer():
    # using perf_counter_ns() to avoid precision loss
    if hasattr(time, 'perf_counter_ns'):
        return time.perf_counter_ns() / 1e9
    return time.perf_counter()

    if len(data) < 3:
        return 0, []
    mean = np.mean(data)
    std = np.std(data, ddof=1)
    if std == 0:
        return 0, []

def measure_keygen(subscription_count):
    """
    Measure Key Generation
    
    return (time_s, pk_bytes, sk_bytes)
    """
    try:
        subscriptions = create_subscriptions(subscription_count)
        attributes = ['username'] + subscriptions
        
        start = precise_timer()
        sk_bytes, pk_bytes = Server.generate_ca(attributes)
        elapsed_time = precise_timer() - start
        
        # check that keys are generated properly
        if not sk_bytes or not pk_bytes:
            raise ValueError("Key generation failed")
            
        return elapsed_time, len(pk_bytes), len(sk_bytes)
    except Exception as e:
        print(f"KeyGen failed: {e}")
        return float('inf'), 0, 0

def measure_issuance(subscription_count):
    """
    Measure Issuance
    """
    try:
        subscriptions = create_subscriptions(subscription_count)
        attributes = ['username'] + subscriptions
        
        server_sk, server_pk = Server.generate_ca(attributes)
        pk_size = len(server_pk)
        server = Server()
        client = Client()
        username = 'alice'

        # IssuePrepare: client prepares registration
        start_time = precise_timer()
        req_bytes, state = client.prepare_registration(server_pk, username, subscriptions)
        t1 = precise_timer() - start_time
        req_size = len(req_bytes)

        # IssueSign: server processes registration  
        start_time = precise_timer()
        resp_bytes = server.process_registration(server_sk, server_pk, req_bytes, username, subscriptions)
        t2 = precise_timer() - start_time
        resp_size = len(resp_bytes)

        # IssueObtain: client processes response - local unblinding operation
        start_time = precise_timer()
        cred_bytes = client.process_registration_response(server_pk, resp_bytes, state)
        t3 = precise_timer() - start_time
        cred_size = len(cred_bytes)

        return {
            'prepare_time': t1,
            'sign_time': t2,
            'obtain_time': t3,
            'total_time': t1 + t2 + t3,
            'pk_size': pk_size,
            'request_size': req_size,
            'response_size': resp_size,
            'credential_size': cred_size,
            'total_comm_bytes': pk_size + req_size + resp_size
        }
    except Exception as e:
        print(f"Issuance failed: {e}")
        return {
            'prepare_time': float('inf'), 'sign_time': float('inf'), 'obtain_time': float('inf'),
            'total_time': float('inf'), 'pk_size': 0, 'request_size': 0, 'response_size': 0,
            'credential_size': 0, 'total_comm_bytes': 0
        }

def measure_show_and_verify(subscription_count):
    """
    Measure Disclosure Proof (Showing) and Verification
    """
    try:
        subscriptions = create_subscriptions(subscription_count)
        attributes = ['username'] + subscriptions
        
        server_sk, server_pk = Server.generate_ca(attributes)
        server = Server()
        client = Client()
        username = 'alice'
        
        # complete registration flow
        req_bytes, state = client.prepare_registration(server_pk, username, subscriptions)
        resp_bytes = server.process_registration(server_sk, server_pk, req_bytes, username, subscriptions)
        cred_bytes = client.process_registration_response(server_pk, resp_bytes, state)
        
        # disclose actual subscription attributes only
        disclosed_types = subscriptions.copy()  # subscribed attributes
        
        message = b"some location request"
        message_size = len(message)
        
        # measure showing = creating proof + message
        start_time = precise_timer()
        proof_bytes = client.sign_request(server_pk, cred_bytes, message, disclosed_types)
        t_show = precise_timer() - start_time
        proof_size = len(proof_bytes)
        
        # show communication cost = proof + message being signed
        show_comm_cost = proof_size + message_size
        
        # measure verification 
        start_time = precise_timer()
        verify_result = server.check_request_signature(server_pk, message, disclosed_types, proof_bytes)
        t_verify = precise_timer() - start_time
        
        if not verify_result:
            print("Warning: Verification failed!")
        
        # verify communication cost: receives proof + message, sends result back
        verify_result_bytes = len(jsonpickle.encode(verify_result).encode())
        verify_comm_cost = proof_size + message_size + verify_result_bytes
        
        return {
            'show_time': t_show,
            'verify_time': t_verify,
            'show_comm_cost': show_comm_cost,
            'verify_comm_cost': verify_comm_cost,
            'proof_size': proof_size,
            'message_size': message_size,
            'disclosed_count': len(disclosed_types),
            'subscription_count': subscription_count
        }
    except Exception as e:
        print(f"Showing/Verification failed: {e}")
        return {
            'show_time': float('inf'), 'verify_time': float('inf'),
            'show_comm_cost': 0, 'verify_comm_cost': 0,
            'proof_size': 0, 'message_size': 0,
            'disclosed_count': 0, 'subscription_count': subscription_count
        }

print(f"Starting ABC performance evaluation with {N_TRIALS} trials...")
print(f"Subscription counts: {SUBSCRIPTION_COUNTS}")

# operations to measure
operations = ['KeyGen', 'Issuance', 'Show', 'Verify', 'FullFlow']
issuance_steps = ['IssuePrepare', 'IssueSign', 'IssueObtain']

results = {}

# main evaluation loop
for subscription_count in SUBSCRIPTION_COUNTS:
    total_attrs = subscription_count + 2  # 2 for secret_key and username
    print(f"\nTesting with {subscription_count} subscription attributes...")
    
    time_records = {op: [] for op in operations + issuance_steps}
    comm_records = {op: [] for op in operations + issuance_steps}
    
    # tqdm progress bar
    with tqdm(total=N_TRIALS, desc=f"Main operations (subs={subscription_count})") as pbar:
        for trial in range(N_TRIALS):
            # KeyGen
            t_k, pk_size, sk_size = measure_keygen(subscription_count)
            time_records['KeyGen'].append(t_k)
            comm_records['KeyGen'].append(pk_size)

            # Issuance
            issuance_details = measure_issuance(subscription_count)
            time_records['Issuance'].append(issuance_details['total_time'])
            comm_records['Issuance'].append(issuance_details['total_comm_bytes'])
            
            # Issuance steps computation (time) costs
            time_records['IssuePrepare'].append(issuance_details['prepare_time'])
            time_records['IssueSign'].append(issuance_details['sign_time'])
            time_records['IssueObtain'].append(issuance_details['obtain_time'])
            
            # Issuance steps communication costs
            comm_records['IssuePrepare'].append(issuance_details['pk_size'] + issuance_details['request_size'])  # PK + request
            comm_records['IssueSign'].append(issuance_details['response_size'])
            comm_records['IssueObtain'].append(0)

            # Showing and Verification
            show_verify_details = measure_show_and_verify(subscription_count)
            
            time_records['Show'].append(show_verify_details['show_time'])
            comm_records['Show'].append(show_verify_details['show_comm_cost'])
            
            time_records['Verify'].append(show_verify_details['verify_time'])
            comm_records['Verify'].append(show_verify_details['verify_comm_cost'])

            # Full Flow - end-to-end execution of ABC system
            full_time = t_k + issuance_details['total_time'] + show_verify_details['show_time'] + show_verify_details['verify_time']
            # Full communication: KeyGen (PK) + Issuance (PK+req+resp) + Show/Verify (proof+message+result)
            # we subtract proof and message from verify since we already counted them in showing
            full_comm = issuance_details['total_comm_bytes'] + show_verify_details['show_comm_cost'] + show_verify_details['verify_comm_cost'] - show_verify_details['proof_size'] - show_verify_details['message_size']
            
            time_records['FullFlow'].append(full_time)
            comm_records['FullFlow'].append(full_comm)
            
            pbar.update(1)
    
    # store results with statistical analysis
    results[subscription_count] = {
        'time': {},
        'comm': {}
    }
    
    for op in operations + issuance_steps:
        # computation analysis
        arr_t = np.array(time_records[op])
        arr_t = arr_t[np.isfinite(arr_t)]
        if len(arr_t) > 0:
            results[subscription_count]['time'][op] = {
                'mean': arr_t.mean(),
                'sem': arr_t.std(ddof=1) / np.sqrt(len(arr_t)) if len(arr_t) > 1 else 0,
                'std': arr_t.std(ddof=1) if len(arr_t) > 1 else 0,
                'samples': len(arr_t)
            }
        
        # communication analysis
        arr_b = np.array(comm_records[op])
        arr_b = arr_b[np.isfinite(arr_b)]
        if len(arr_b) > 0:
            results[subscription_count]['comm'][op] = {
                'mean': arr_b.mean(),
                'sem': arr_b.std(ddof=1) / np.sqrt(len(arr_b)) if len(arr_b) > 1 else 0,
                'std': arr_b.std(ddof=1) if len(arr_b) > 1 else 0,
                'samples': len(arr_b)
            }

# summary dataframes
time_df_data = []
comm_df_data = []
summary_data = []

for subscription_count in SUBSCRIPTION_COUNTS:
    for op in operations:
        if op in results[subscription_count]['time']:
            time_mean = results[subscription_count]['time'][op]['mean']
            time_sem = results[subscription_count]['time'][op]['sem']
            comm_mean = results[subscription_count]['comm'][op]['mean']
            comm_sem = results[subscription_count]['comm'][op]['sem']
            
            time_df_data.append({
                'Subscriptions': subscription_count,
                'Operation': op,
                'Mean_Time_s': time_mean,
                'StdErr_Time_s': time_sem
            })
            
            comm_df_data.append({
                'Subscriptions': subscription_count,
                'Operation': op,
                'Mean_Bytes': comm_mean,
                'StdErr_Bytes': comm_sem
            })
            
            summary_data.append({
                'Subscriptions': subscription_count,
                'Operation': op,
                'Mean_Time_s': time_mean,
                'StdErr_Time_s': time_sem,
                'Mean_Bytes': comm_mean,
                'StdErr_Bytes': comm_sem
            })

# Issuance steps summary
issuance_summary_data = []
for subscription_count in SUBSCRIPTION_COUNTS:
    for step in issuance_steps:
        if step in results[subscription_count]['time']:
            time_mean = results[subscription_count]['time'][step]['mean']
            time_sem = results[subscription_count]['time'][step]['sem']
            comm_mean = results[subscription_count]['comm'][step]['mean']
            comm_sem = results[subscription_count]['comm'][step]['sem']
            
            issuance_summary_data.append({
                'Subscriptions': subscription_count,
                'Operation': step,
                'Mean_Time_s': time_mean,
                'StdErr_Time_s': time_sem,
                'Mean_Bytes': comm_mean,
                'StdErr_Bytes': comm_sem
            })

# saving summary dataframes
summary_df = pd.DataFrame(summary_data)
summary_df.to_csv(f"{args.output_dir}/abc_performance_summary.csv", index=False)

issuance_summary_df = pd.DataFrame(issuance_summary_data)
issuance_summary_df.to_csv(f"{args.output_dir}/abc_issuance_steps_summary.csv", index=False)

# creating visualization plots
colors = ['skyblue', 'lightgreen', 'coral', 'orange']
color_map = {sub: color for sub, color in zip(SUBSCRIPTION_COUNTS, colors)}

bar_width = 0.2
n_operations = len(operations)
n_sub_counts = len(SUBSCRIPTION_COUNTS)

# Computation Costs Plot
plt.figure(figsize=(14, 8))

bars_by_sub = {sub: [] for sub in SUBSCRIPTION_COUNTS}

for i, operation in enumerate(operations):
    for j, subscription_count in enumerate(SUBSCRIPTION_COUNTS):
        if subscription_count in results and operation in results[subscription_count]['time']:
            time_data = results[subscription_count]['time'][operation]
            
            pos = i + (j - n_sub_counts/2 + 0.5) * bar_width
            
            bar = plt.bar(pos, time_data['mean'], 
                         width=bar_width, color=color_map[subscription_count],
                         yerr=time_data['sem'], capsize=5,
                         label=f'{subscription_count} subscriptions' if i == 0 else "")
            
            height = time_data['mean']
            plt.text(pos, height + 0.01 * max([results[sc]['time'][op]['mean'] 
                                              for sc in SUBSCRIPTION_COUNTS 
                                              for op in operations 
                                              if sc in results and op in results[sc]['time']]), 
                    f"{height:.4f}s", ha='center', va='bottom', fontsize=10)
            
            if i == 0:
                bars_by_sub[subscription_count] = bar

plt.xlabel('Operation', fontsize=12)
plt.ylabel('Time (in seconds)', fontsize=12)
plt.title('ABC Computation Costs', fontsize=14)
plt.xticks(np.arange(n_operations), operations)
plt.legend([bars_by_sub[sub][0] for sub in SUBSCRIPTION_COUNTS if sub in bars_by_sub], 
           [f'{sub} subscriptions' for sub in SUBSCRIPTION_COUNTS if sub in bars_by_sub],
           title='Subscription Attributes Count')
plt.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(f"{args.output_dir}/abc_computation_costs.png", dpi=300)

# Communication Costs Plot
plt.figure(figsize=(14, 8))

bars_by_sub = {sub: [] for sub in SUBSCRIPTION_COUNTS}

for i, operation in enumerate(operations):
    for j, subscription_count in enumerate(SUBSCRIPTION_COUNTS):
        if subscription_count in results and operation in results[subscription_count]['comm']:
            comm_data = results[subscription_count]['comm'][operation]
            
            pos = i + (j - n_sub_counts/2 + 0.5) * bar_width
            
            bar = plt.bar(pos, comm_data['mean'], 
                         width=bar_width, color=color_map[subscription_count],
                         yerr=comm_data['sem'], capsize=5,
                         label=f'{subscription_count} subscriptions' if i == 0 else "")
            
            height = comm_data['mean']
            plt.text(pos, height + 0.01 * max([results[sc]['comm'][op]['mean'] 
                                              for sc in SUBSCRIPTION_COUNTS 
                                              for op in operations 
                                              if sc in results and op in results[sc]['comm']]), 
                    f"{int(height)}B", ha='center', va='bottom', fontsize=10)
            
            if i == 0:
                bars_by_sub[subscription_count] = bar

plt.xlabel('Operation', fontsize=12)
plt.ylabel('Bytes Exchanged', fontsize=12)
plt.title('ABC Communication Costs', fontsize=14)
plt.xticks(np.arange(n_operations), operations)
plt.legend([bars_by_sub[sub][0] for sub in SUBSCRIPTION_COUNTS if sub in bars_by_sub], 
           [f'{sub} subscriptions' for sub in SUBSCRIPTION_COUNTS if sub in bars_by_sub],
           title='Subscription Attributes Count')
plt.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(f"{args.output_dir}/abc_communication_costs.png", dpi=300)

print(f"\nResults saved to {args.output_dir}/")
print("Performance evaluation done!")