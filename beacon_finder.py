#!/usr/bin/env python3

'''
'   beacon_finder.py
'
'   THIS SCRIPT IS PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF ANY
' 	KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR A
' 	PARTICULAR PURPOSE. ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF THE
'   AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF ANY
' 	SUCH DAMAGE. IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
' 	LIABILITY, THEN DO NOT DOWNLOAD OR USE THE SCRIPT. NO TECHNICAL SUPPORT
' 	WILL BE PROVIDED.
'
'   RITA-like beacon detection based on https://github.com/ppopiolek/c2-detection-using-statistical-analysis/blob/main/RITA_pcap.ipynb  
'    and https://github.com/Cyb3r-Monk/RITA-J/blob/main/C2%20Detection%20-%20HTTP.ipynb  
'
'   - If beacon traffic ==> uniform distribution and small Median Absolute Deviation of time deltas
'   - If user traffic ==> skewed distribution and large Median Absolute Deviation of time deltas
'''

import math
import pandas as pd
import numpy as np
import warnings
import sys
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

class Color:

    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    purple = '\033[95m'
    magenta = "\033[35m"
    cyan = "\033[36m"
    bgmagenta = "\033[45m"
    bgyellow = "\033[43m"
    bgred = "\033[41m"
    lightred = "\033[91m"
    lightgreen = "\033[92m"
    end = '\033[0m'

# Read CSV file
# df = pd.read_csv('proxy1.csv', sep=',', names=['timestamp','source','username','dest_ip','category','METHOD','port','domain','uri','filetype','agent','bytes_received','bytes_sent'])
df = pd.read_csv('proxy1.csv', sep=',', names=['timestamp','source_ip','username','dest_ip','category','METHOD','port','domain','uri','filetype','agent','bytes_received','bytes_sent'], parse_dates=['timestamp'], date_parser=lambda x: pd.to_datetime(x, format='%Y-%m-%d-%H:%M:%S'))
# print(f'{Color.blue}DEBUG LIST{Color.end}')
# print(df.head(20))
# Filter out rows where 'username' or 'dest_ip' columns contain '-'
df = df.loc[(df['username'] != '-') & (df['dest_ip'] != '-')]

# Filter Required Columns
time = 'timestamp'
src = 'username'
# dst = 'dest_ip'
dst = 'domain'

df = df.loc[:, [time, src, dst]]
# df.info()

# Grouping the Connections
df = df.groupby([src, dst]).agg(list)
# df.head(30)

# Reset the Indexes
df.reset_index(inplace=True)
# df.head(20)

# Calculate connection count
count = 'Count'
df[count] = df[time].apply(lambda x: len(x))
# df.head(20)

print(f'{Color.blue}DEBUG LIST{Color.end}')
print(df.head(10))

# Remove short sessions
df = df.loc[df[count] > 36]
df.reset_index(inplace=True)
df = df.loc[:, [src, dst, time, count]]
# df.head(20)

# Convert timedelta objects to strings and remove '0 days' part of values
# NOTE this doesnt work
# df['Deltas'] = df['Deltas'].apply(lambda x: [str(y).split(' days ')[-1] for y in x])

# Calculate time deltas
dlt = 'Deltas'
df[dlt] = df[time].apply(lambda x: pd.Series(x).diff().dropna().tolist())
# df.head(20)

# Generate variables required for score calculation
df['Low'] = df[dlt].apply(lambda x: np.percentile(np.array(x), 20))
df['Mid'] = df[dlt].apply(lambda x: np.percentile(np.array(x), 50))
df['High'] = df[dlt].apply(lambda x: np.percentile(np.array(x), 80))
df['BowleyNum'] = df['Low'] + df['High'] - 2 * df['Mid'] 
df['BowleyDen'] = df['High'] - df['Low'] 
df['Skew'] = df[['Low', 'Mid', 'High', 'BowleyNum', 'BowleyDen']].apply(lambda x: x['BowleyNum'] / x['BowleyDen'] if x['BowleyNum'] != 0 and x['Mid'] != x['Low'] and x['Mid'] != x['High'] else 0.0, axis=1)
#df['Madm'] = df[dlt].apply(lambda x: np.median(np.absolute(np.array(x) - np.median(np.array(x)))))
#df['Madm'] = df[dlt].apply(lambda x: np.median(np.absolute(np.array(x).astype('timedelta64[s]') - np.median(np.array(x).astype('timedelta64[s]')))))
df['Madm'] = df[dlt].apply(lambda x: np.median(np.absolute(np.array([y.total_seconds() for y in x]) - np.median(np.array([y.total_seconds() for y in x])))))
#df['ConnDiv'] = df[time].apply(lambda x: x[-1] - x[0])
df['ConnDiv'] = df[time].apply(lambda x: (x[-1] - x[0]).total_seconds())
# df.head(5)

# Calculating the score
score = 'Score'
df['SkewScore'] = 1.0 - abs(df['Skew'])
df['MadmScore'] = 1.0 - df['Madm']/30.0
df['MadmScore'] = df['MadmScore'].apply(lambda x: 0 if x < 0 else x)
df['ConnCountScore'] = 10 * (df[count]) / df['ConnDiv']
df['ConnCountScore'] = df['ConnCountScore'].apply(lambda x: 1.0 if x > 1.0 else x)
df[score] = (((df['SkewScore'] + df['MadmScore'] + df['ConnCountScore']) / 3.0) * 1000) / 1000
df.sort_values(by= 'Score', ascending=False, inplace=True) #, ignore_index=True)  # ignore_index not support on prod 
df[[score, count, src, dst, dlt]].head(5)

print(f'{Color.blue}SCORES{Color.end}')
print(df[[score, count, src, dst, dlt]].head(20))

# Remove redundant column
df = df.loc[:, [score, count, src, dst, dlt]]
# df.head(20)

# Display suspiciuos connections
print(f'{Color.bgred}Possible Beacons{Color.end}')
print(df.loc[df[score] > 0.7])

# Visualization
# import matplotlib.pyplot as plt
# import seaborn as sns
# headDeltas = df.head(1)[dlt].tolist()
# midDeltas = df.loc[df[count] > 500].tail(1)[dlt].tolist()
# sns.set_style('darkgrid')
# sns.distplot(headDeltas, hist = False, label= 'Cobalt Strike')
# sns.distplot(midDeltas, hist = False, label = 'Benign')
# plt.legend()