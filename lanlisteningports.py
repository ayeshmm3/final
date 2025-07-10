
import paramiko
import os
import re
import pandas as pd
from dotenv import load_dotenv

def run_netstat(): 
    load_dotenv()

    hostname = os.getenv("HOSTNAME")
    password = os.getenv("PASSWORD")
    username = "root"

    command = "netstat -tulpan"

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password)
        _stdin, _stdout, _stderr = client.exec_command(command)
        output = _stdout.read().decode().strip()
        error = _stderr.read().decode().strip()
        
        # Parsing and organizing the Output into clean data frame 

        if output:
            lines = output.split('\n')
            data = []
            for line in lines: 
                if line.startswith('Proto') or ('Active') in line or not line.strip():
                    continue
                parts = re.split(r'\s+', line, maxsplit=6)
                if len(parts) >= 6:
                    proto, recv_q, send_q, local, foreign, state = parts[:6]
                    program = parts[6] if len(parts) == 7 else ''
                    data.append([proto, local, foreign, state, program])
            df = pd.DataFrame(data, columns=['Protocol', 'Local', 'Foreign', 'State', 'Program'])
           
            # Flagging any suspicious entries
            df['Flagged'] = (
                df['Local'].str.startswith('10.85') & df['State'].isin(['LISTEN', 'ESTABLISHED'])
            ) | (
                ~df['Local'].str.startswith(('0.0.0.0', '127.'))
            )
            flagged_df = df[df['Flagged']] 
            unflagged_df = df[~df['Flagged']]
          
            
            # Writing Out to File "final_results.txt"
            with open("final_results.txt", "w") as f:
                f.write("=== Flagged Connections ===\n")
                f.write(flagged_df.to_string(index=False))
                f.write("\n\n=== Unflagged Connections ===\n")
                f.write(unflagged_df.to_string(index=False))

            print("Results written to final.txt")
            
        elif error:
            print(error)

    except Exception as e:
        print(f"SSH connection failed: {e}")
    finally:
        client.close()


if __name__ == '__main__':
    run_netstat()

