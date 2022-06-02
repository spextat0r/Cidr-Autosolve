cdr_17 = [0, 128, 256]
cdr_18 = [0, 64, 128, 192, 256]
cdr_19 = [0, 32, 64, 96, 128, 160, 192, 224, 256]
cdr_20 = [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256]
cdr_21 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256]
cdr_22 = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160, 164, 168, 172, 176, 180, 184, 188, 192, 196, 200, 204, 208, 212, 216, 220, 224, 228, 232, 236, 240, 244, 248, 252, 256]
cdr_23 = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 256]
ips_in_scope = []

#read files
"""with open('', 'r') as f:
    scope_data = f.read()
    f.close()

with open('', 'r') as f:
    out_of_scope_data = f.readlines()
    f.close()
"""

#logic
scope_data = "10.265.0.0/16"
out_of_scope_data = ["10.265.99.0/24", "10.265.111.0/24", "10.265.200.0/24"]
if scope_data.find('/16') != -1: # check if the iprange is a /16
    # if it is a /16 we need to get the first 2 octects seperated
    substring = "."
    idx_of_2nd_per = scope_data.find(substring, scope_data.find(substring) + 1)
    first_2_octects = scope_data[:idx_of_2nd_per+1] # first_2_octects will be the var that holds eg 192.168.


    #counting logic now
    #the counter variable is what would be the third octet
    counter = 0
    for arr_count in out_of_scope_data:
        third_octect = arr_count[idx_of_2nd_per+1:]
        third_octect = int(third_octect[:third_octect.find('.')])

        while counter < third_octect:

            if ((counter + 128) <= third_octect and (counter + 128) in cdr_17):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/17")
                #print(first_2_octects + str(counter) + ".0/17")
                counter += 128
            elif ((counter + 64) <= third_octect and (counter + 64) in cdr_18):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/18")
                #print(first_2_octects + str(counter) + ".0/18")
                counter += 64
            elif ((counter + 32) <= third_octect and (counter + 32) in cdr_19):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/19")
                #print(first_2_octects + str(counter) + ".0/19")
                counter += 32
            elif ((counter + 16) <= third_octect and (counter + 16) in cdr_20):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/20")
                #print(first_2_octects + str(counter) + ".0/20")
                counter += 16
            elif ((counter + 8) <= third_octect and (counter + 8) in cdr_21):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/21")
                #print(first_2_octects + str(counter) + ".0/21")
                counter = counter + 8
            elif ((counter + 4) <= third_octect and (counter + 4) in cdr_22):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/22")
                #print(first_2_octects + str(counter) + ".0/22")
                counter += 4
            elif ((counter + 2) <= third_octect and (counter + 2) in cdr_23):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/23")
                #print(first_2_octects + str(counter) + ".0/23")
                counter += 2
            else:
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/24")
                #print(first_2_octects + str(counter) + ".0/24")
                counter += 1
            if (counter == third_octect):
                counter += 1

    while counter < 256:
        if ((counter + 128) in cdr_17):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/17")
            #print(first_2_octects + str(counter) + ".0/17")
            counter += 128
        elif ((counter + 64) in cdr_18):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/18")
            #print(first_2_octects + str(counter) + ".0/18")
            counter += 64
        elif ((counter + 32) in cdr_19):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/19")
            #print(first_2_octects + str(counter) + ".0/19")
            counter += 32
        elif ((counter + 16) in cdr_20):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/20")
            #print(first_2_octects + str(counter) + ".0/20")
            counter += 16
        elif ((counter + 8) in cdr_21):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/21")
            #print(first_2_octects + str(counter) + ".0/21")
            counter = counter + 8
        elif ((counter + 4) in cdr_22):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/22")
            #print(first_2_octects + str(counter) + ".0/22")
            counter += 4
        elif ((counter + 2) in cdr_23):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/23")
            #print(first_2_octects + str(counter) + ".0/23")
            counter += 2
        else:
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/24")
            #print(first_2_octects + str(counter) + ".0/24")
            counter += 1

with open('in_scope_ranges.txt', 'w') as f:
    for item in ips_in_scope:
        f.write("%s\n" % item)
    f.close()