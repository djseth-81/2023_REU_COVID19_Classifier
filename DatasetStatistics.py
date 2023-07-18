"""
### Dataset Statistics ###
Author: Seth Johnson
Date: 07-14-2023
"""
from CSVHandler import *
import matplotlib.pyplot as plt

### Variable Declaration
permSpread = [] # Array of arrays representing the permissions that a given apk file requests
osPermKeys = [] # Key values for all permissions associated with the base AndroidOS devkit
osPermSpread = [] # Array of arrays representing permission spread of all apk base AndroidOS requests
benignPerms = [] # Array representing how many times a benign APK file requests a given permission. The index of each value represents how many times a permission in permSpread is requested.
maliciousPerms = [] # Array representing how many times a malicious APK file requests a given permission. The index of each value represents how many times a permission in permSpread is requested.
benignPerms_OS = [] # Array representing how many times a benign APK file requests a given AndroidOS permission
maliciousPerms_OS = [] # Array representing how many times a malicious APK file requests a given AndroidOS permission
maliciousSpread = [] # Array of arrays that represent all permissions that a malicious APK file requests
benignSpread = [] # Array of arrays that represent all permissions that a benign APK file requests
benignSpread_OS = [] # Array of arrays representing all AndroidOS permissions that a benign APK file requests
maliciousSpread_OS = [] # Array of arrays representing all AndroidOS permissions that a malicious APK file requests
benignSums = [] # Array representing the total sum of all permissions a given benign apk file requests
maliciousSums = [] # Array represnting total sum of all permissions a given malicious apk file requests
yBenign = [] # Array representing how many APK files request a certain number of permissions. Each index correlates to the index in `x`, and the value at each index represents how many benign APK files request that many permissions
yMalicious = [] # Array representing how many APK files request a certain number of permissions. Each index correlates to the index in `x`, and the value at each index represents how many malicious APK files request that many permissions

### UDF Declaration
def preVisualPrep(permKeys, apks, perms, labels):
    global permSpread
    global osPermSpread
    global osPermKeys
    global benignPerms
    global benignPerms_OS
    global benignSpread
    global benignSpread_OS
    global benignSums
    global maliciousPerms
    global maliciousPerms_OS
    global maliciousSpread
    global maliciousSpread_OS
    global maliciousSums
    try:
        for i in range(len(perms)):
            permSpread.append(perms[i][1:]) # cleaning permission spread of AV Rank and total permission requests

            # Creating keys and permSpread arrays specifically for AndroidOS-based permissions
            arr = [] # subarray for our osPermSpread
            for ef in range(len(permKeys)):
                if permKeys[ef].lower().startswith("android.permission"):
                    if permKeys[ef] not in osPermKeys: # keeps from multiplying immensely
                        osPermKeys.append(permKeys[ef]) # Builds osPerms key array
                    arr.append(perms[i][ef])
            osPermSpread.append(arr) # updating osPermSpread with our subarray
        benignPerms = [0 for _ in range(len(permKeys))]
        maliciousPerms = [0 for _ in range(len(permKeys))]
        benignPerms_OS = [0 for _ in range(len(osPermKeys))]
        maliciousPerms_OS = [0 for _ in range(len(osPermKeys))]
        for i in range(len(apks)):
            if labels[i] > 0:
                maliciousSpread.append(permSpread[i]) # Sorting out malicious permission spreads
                maliciousSpread_OS.append(osPermSpread[i]) # ...and for OS specific permissions
                for j in range(len(permSpread[i])): 
                    maliciousPerms[j] += permSpread[i][j] # building an array of ints representing malicious requests FE permission
                # restricting to only AndroidOS permissions...
                for j in range(len(osPermSpread[i])): 
                    maliciousPerms_OS[j] += osPermSpread[i][j]
            else:
                benignSpread.append(permSpread[i]) # Sorting out benign permission spreads
                benignSpread_OS.append(osPermSpread[i]) # ...and for OS specific permissions
                for j in range(len(permSpread[i])): 
                    benignPerms[j] += permSpread[i][j] # building an array of ints representing benign requests FE permission
                # restricting to only AndroidOS permissions...
                for j in range(len(osPermSpread[i])):
                    benignPerms_OS[j] += osPermSpread[i][j]
        return 1
    
    except Exception as e:
        print(f"### CONSOLE: Failure occured.\n{e}\nExiting...")
        return 0

def visualize(arrs, lbls=[], title=None, x_Axs=None, y_Axs=None, save=False, flip=False):
    """
    @Description: Utilizes Matplotlib.pyplot to provide superimposed plots for my research

    @params
    xArr:= Array used for plotting along the x axis
    yArrs:= Array consisting of all values that wish to be superimposed on the same image
    title:= String used to label the graph. Defaults to None
    save:= Boolean that determines if the plot is to be saved as a .png. title must be provided if set to True. Defaults to False
    flip:= Boolean to flip the graph to a horizontal bar graph. Defaults to False
    x_Axs:= String to label the X-axis of a plot
    y_Axs:= String to label the y-axis of a plot

    @returns 1 if successful, 0 Otherwise
    """
    width = 0.5 # Designates the width of the bar

    # Ensuring array sizes matches
    if len(arrs[0]) != len(arrs[1]):
        raise Exception(f"Array sizes do not match!\n Expected size: {len(arrs[0])}")
        return 0

    if flip:
        for i, arr in enumerate(arrs):
            plt.barh(np.arange(len(arr)) + (width * i), arr, width, label=i)
        if len(lbls) != 0:
            plt.yticks(np.arange(len(lbls)), lbls) # associating indicies with xArr
    else:
        for i, arr in enumerate(arrs):
            plt.bar(np.arange(len(arr)) + (width * i), arr, width, label=i)
        if len(lbls) != 0:
            plt.xticks(np.arange(len(lbls)), lbls) # associating indicies with xArr

    if x_Axs != None:
        plt.xlabel(x_Axs)
    if y_Axs != None:
        plt.ylabel(y_Axs)

    if title != None:
        plt.title(title)

    plt.legend()

    if save:
        if title == None:
            raise Exception("No title provided, plot will not be saved.")
            return 0
        plt.savefig(f"2023_REU_Workspace/GRAPHS/{title}.png", dpi=300, bbox_inches="tight")

    plt.show()

    return 1

def preModelingVisuals(permKeys, apks, perms, labels):
    preVisualPrep(permKeys, apks, perms, labels)
    try:
        # Collecting the sum of each array in malicious/benignSpread
        benignSums = [sum(i) for i in benignSpread]
        maliciousSums = [sum(i) for i in maliciousSpread]

        # Building the x-array to display each APK's total permission request, distinguished by AV Rank > 0
        x = [i for i in range(max(maliciousSums) + 1)] if maliciousSums > benignSums else [i for i in range(max(benignSums) + 1)]

        # Building y-arrays to display each APK's total permission request, distinguished by AV Rank > 0
        yBenign = [0 for _ in range(len(x))]
        yMalicious = [0 for _ in range(len(x))]

        for i in benignSums:
            yBenign[i] += 1

        for i in maliciousSums:
            yMalicious[i] += 1

        ### Plotting the total permissions requested by a given apk, organized based off an AV rank > 0

        # plt.bar([i for i in range(len(benignSums))], benignSums, label="AV Rank = 0")
        # plt.bar([i for i in range(len(maliciousSums))], maliciousSums, label="AV Rank > 0")
        # plt.xlabel("APK File")
        # plt.ylabel("Quantity of requested permissions")
        # plt.title("Total number of permissions requested for a given APK file.")
        # plt.legend()
        # plt.savefig("TotalPermissionsGraphed.png", dpi=300, bbox_inches = "tight")
        # plt.show()

        ### Plotting how many apps requested a given quantity of permissions

        # Frequency
        title = "Frequency of APK Files requesting some number of permissions"
        xLabel = "Total permissions requested per APK file"
        yLabel = "Frequency of APK files"
        # visualize([yBenign, yMalicious], title=title, save=True, x_Axs=xLabel, y_Axs=yLabel)

        # Frequency up to 60 permissions requested
        title = "Frequency of APK Files requesting up to 60 permissions"
        # visualize([yBenign[:60], yMalicious[:60]], title=title, save=True, x_Axs=xLabel, y_Axs=yLabel)

        # ...Normalized
        title = "Normalized Frequency of APK Files requesting some number of permissions"
        yLabel = "Normalized frequency of APK files"
        # visualize([[i / max(yBenign) for i in yBenign], [i / max(yMalicious) for i in yMalicious]], title=title, save=True, x_Axs=xLabel, y_Axs=yLabel)

        # ...Normalized for up to 60 permissions
        title = "Normalized Frequency of APK files requesting up to 60 permissions"
        # visualize([[i / max(yBenign) for i in yBenign[:60]], [i / max(yMalicious) for i in yMalicious[:60]]], title=title, save=True, x_Axs=xLabel, y_Axs=yLabel)

        # ...Proportioned based on the quantity of benign/malicious APKs respectively
        title = "Proportional Frequency of APK Files requesting some number of permissions"
        yLabel = "Proportional Frequency of APK files"
        # visualize([[i / len(benignSpread) for i in yBenign], [i / len(maliciousSpread) for i in yMalicious]], title=title, save=True, x_Axs=xLabel, y_Axs=yLabel)

        # Plotting proportional frequency of APK files that requested up to 60 permissions
        title = "Proportional Frequency of APK files requesting up to 60 permissions"
        visualize([[i / len(benignSpread) for i in yBenign[:60]], [i / len(maliciousSpread) for i in yMalicious[:60]]], title=title, save=True, x_Axs=xLabel, y_Axs=yLabel)

        ### Plotting the frequency of requests FE permission found during analysis

        # Frequency of applications requesting a given permission
        title = "Top 15 most popular permissions requested by APK files"
        xLabel = "Frequency of APK File requests"
        yLabel = "Permissions"
        visualize(
            [
                sorted(benignPerms, reverse=True)[:15], 
                sorted(maliciousPerms, reverse=True)[:15]
            ],
            [permKeys[1:][benignPerms.index(i)] for i in sorted(benignPerms, reverse=True)[:15]],
            title=title,
            x_Axs=xLabel,
            y_Axs=yLabel,
            save=True,
            flip=True
        )

        # proportion of applications requesting a given permission
        title = "Proportional frequency of a given permission requested by APK files"
        xLabel = "Proportion of APK File requests"
        # visualize(
        #     [
        #         [i / len(benignPerms) for i in sorted(benignPerms, reverse=True)[:10]],
        #         [i / len(maliciousPerms) for i in sorted(maliciousPerms, reverse=True)[:10]]
        #     ],
        #     [permKeys[1:][benignPerms.index(i)] for i in sorted(benignPerms, reverse=True)[:10]],
        #     title=title,
        #     x_Axs=xLabel,
        #     y_Axs=yLabel,
        #     save=True,
        #     flip=True
        # )

        ### Re-Doing yBenign and yMalicious for our OS specific permission spreads

        benignSums = [sum(i) for i in benignSpread_OS]
        maliciousSums = [sum(i) for i in maliciousSpread_OS]

        # Resetting y arrays
        yBenign = [0 for _ in range(len(x))]
        yMalicious = [0 for _ in range(len(x))]

        for i in benignSums:
            yBenign[i] += 1

        for i in maliciousSums:
            yMalicious[i] += 1

        ### Re-Plotting for AndroidOS specific permission spreads

        # resetting summation arrays
        benignSums = [sum(i) for i in benignSpread_OS]
        maliciousSums = [sum(i) for i in maliciousSpread_OS]

        # Resetting y arrays
        yBenign = [0 for _ in range(len(x))]
        yMalicious = [0 for _ in range(len(x))]

        for i in benignSums:
            yBenign[i] += 1

        for i in maliciousSums:
            yMalicious[i] += 1

        # Proportional frequency of APK files that requested only base AndroidOS permissions
        title = "Proportional frequency of APK files that request only base AndroidOS permissions"
        xLabel = "Quantity of AndroidOS permissions requested"
        yLabel= "Proportional frequency of APK files"
        # visualize([[i / len(benignSpread_OS) for i in yBenign], [i / len(maliciousSpread_OS) for i in yMalicious]], title=title, x_Axs=xLabel, y_Axs=yLabel, save=True)

        # Proportional frequency of APK files that requested only base AndroidOS permissions up to 60 times
        title = "Proportional frequency of APK files that request only base AndroidOS permissions up to 60 times"
        visualize([[i / len(benignSpread_OS) for i in yBenign[:60]], [i / len(maliciousSpread_OS) for i in yMalicious[:60]]], title=title, x_Axs=xLabel, y_Axs=yLabel, save=True)

        # Frequency of applications requesting base AndroidOS permissions
        title = "Frequency of requests for each base AndroidOS permission"
        xLabel = "AndroidOS Permissions"
        yLabel = "Frequency of APK file requests"
        # visualize(
        #     [sorted(benignPerms_OS, reverse=True), sorted(maliciousPerms_OS, reverse=True)],
        #     [osPermKeys[benignPerms_OS.index(i)] for i in sorted(benignPerms_OS, reverse=True)],
        #     title=title,
        #     x_Axs=xLabel,
        #     y_Axs=yLabel,
        #     flip=True
        # )

        # Frequency of applications requesting the first 30 base AndroidOS permissions
        title = "Frequency of the top 10 most requested base AndroidOS Permissions"
        # visualize(
        #     [
        #         sorted(benignPerms_OS, reverse=True)[:10],
        #         sorted(maliciousPerms_OS, reverse=True)[:10]
        #     ],
        #     [osPermKeys[benignPerms_OS.index(i)] for i in sorted(benignPerms_OS, reverse=True)[:10]],
        #     title=title,
        #     x_Axs=xLabel,
        #     y_Axs=yLabel,
        #     save=True,
        #     flip=True
        # )
        # Proportion of applications requesting the first 30 base AndroidOS permissions
        title = "Proportional frequency of the top 15 most requested base AndroidOS Permissions"
        visualize(
            [
                [i / len(benignPerms_OS) for i in sorted(benignPerms_OS, reverse=True)[:15]],
                [i / len(maliciousPerms_OS) for i in sorted(maliciousPerms_OS, reverse=True)[:15]]
            ],
            [osPermKeys[benignPerms_OS.index(i)] for i in sorted(benignPerms_OS, reverse=True)[:15]],
            title=title,
            x_Axs=xLabel,
            y_Axs=yLabel,
            save=True,
            flip=True
        )
        return 1
    except Exception as e:
        print(f"### CONSOLE: An error occured.\n{e}\nExiting...")
        return 0

def displayStats(apks, labels):
    # How many APKs are malicious?
    totalAPKs = len(apks)
    totalBadAPKs = sum([1 if item > 0 else 0 for item in labels])
    print(f"We analyzed {totalAPKs} APKs")
    print(f"Out of that, {totalBadAPKs} were flagged as malicious. This is according to the dataset provided by Wang et al 2021.")
    print(f"Which means about {((totalBadAPKs / totalAPKs) * 100):.2f}% of all analyzed APKs are labeled as malicious.")

if __name__ == "__main__":

    apkData, keys, permKeys, apks, avRanks, perms, labels = preprocessing("2023_REU_Workspace/COVID19_APK_Data_06-2023.csv")
    preModelingVisuals(permKeys, apks, perms, labels)
    displayStats(apks, labels)