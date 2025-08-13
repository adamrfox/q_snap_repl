# q_snap_repl
A project to replicate Qumulo Snapshots

This goal of this project is to automate the migration of data between Qumulo clusters including snapshots.  Data is moved via an NFS or SMB client using (by default) rsync and robocopy respectively, however the user can specify another program.  It uses the Qumulo API to discover the snapshots on the source, and to re-create those snapshots on the target with the same expiration dates.

The code uses the'keyring' Python module for authentication.  This module may need to be installed in a particuarly environment.  The rest should be standard Python modules.  The code requires Python 3.x.

<PRE>
Usage: q_snap_repl.py [-hDl] [-c creds] [-s src_creds] [-d dest_creds] [-r repl_cmd] [-i id_list] [-t threads] src dest
-h | --help : Prints this message
-D | --DEBUG: Debug mode, Creates extra output in a file called debug.out
-l | --logging : Enables replication logging
-c | --creds : Supply credentials if they are the same on both clusters [user[:password]]
-s | --src_creds : Supply credentials of the source if different [user[:password]]
-d | --dest_creds : Supply credentials of the destination if different [user[:password]]
-r | --repl_cmd : Use a custom replication command
-i | --id_list : Only replicate a comma separated list of snapshot IDs
-t | --threads : Change the number of threads (default robocopy command only).  [Def: 8]
src : Source Cluster Name and Path [name:path or UNC path to share]
dest: Destingation Cluster Name and Path [name:path or UNC path to share]
</PRE>

## Authentication
The script will ask for a username and password for each Qumulo.  If the name is the same the -c flag can be used, otherwise -s and -d can be used to specify the user (and password if desired) on the CLI.  Once the credentials have been entered once, the script will offer to store them in the user's keyring for future use.  If that is selected, the password will be pulled from there on subseqent runs.

## Filesystem Permissions
In order to do a proper migration the script must be run as a user that has permission to read all of the data on the source as well as write and change ownership and permissions on the target.  There are multiple ways to do this based on the individual environment, with the simplest being running it as root or Administrator.  But any user that would be used for migrations should work fine.

## Minimial Qumulo API Priviledges
<PRE>
FS_ATTRIBUTES_READ (both)
SMB_SHARE_READ (both)
NFS_EXPORT_READ (both)
SNAPSHOT_READ (source)
SNAPSHOT_WRITE (destination)
</PRE>
