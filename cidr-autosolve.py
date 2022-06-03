import sys # solely so we can use command line arguments
import re # so I can sanatize your inputs

cdr_17 = [0, 128, 256]
cdr_18 = [0, 64, 128, 192, 256]
cdr_19 = [0, 32, 64, 96, 128, 160, 192, 224, 256]
cdr_20 = [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256]
cdr_21 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256]
cdr_22 = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160, 164, 168, 172, 176, 180, 184, 188, 192, 196, 200, 204, 208, 212, 216, 220, 224, 228, 232, 236, 240, 244, 248, 252, 256]
cdr_23 = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 256]
ips_in_scope = []

#this is the logic and rules that define cidr
def do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data):
    for arr_count in out_of_scope_data:  # this for loop goes through the out_of_scope_data list so that we can move the counter up to the point of out of scope and then skip the out of scope ip
        third_octect = arr_count[idx_of_2nd_per + 1:] #this will get the third octect of the out of scope ip we are currently using in the out_of_scope_ips list
        third_octect = int(third_octect[:third_octect.find('.')])

        while counter < third_octect: # the counter starts at whatever third octect
            if ((counter + 128) <= third_octect and (counter + 128) in cdr_17):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/17")
                # print(first_2_octects + str(counter) + ".0/17")
                counter += 128
            elif ((counter + 64) <= third_octect and (counter + 64) in cdr_18):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/18")
                # print(first_2_octects + str(counter) + ".0/18")
                counter += 64
            elif ((counter + 32) <= third_octect and (counter + 32) in cdr_19):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/19")
                # print(first_2_octects + str(counter) + ".0/19")
                counter += 32
            elif ((counter + 16) <= third_octect and (counter + 16) in cdr_20):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/20")
                # print(first_2_octects + str(counter) + ".0/20")
                counter += 16
            elif ((counter + 8) <= third_octect and (counter + 8) in cdr_21):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/21")
                # print(first_2_octects + str(counter) + ".0/21")
                counter = counter + 8
            elif ((counter + 4) <= third_octect and (counter + 4) in cdr_22):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/22")
                # print(first_2_octects + str(counter) + ".0/22")
                counter += 4
            elif ((counter + 2) <= third_octect and (counter + 2) in cdr_23):
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/23")
                # print(first_2_octects + str(counter) + ".0/23")
                counter += 2
            else:
                if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                    ips_in_scope.append(first_2_octects + str(counter) + ".0/24")
                # print(first_2_octects + str(counter) + ".0/24")
                counter += 1
            if (counter == third_octect):
                counter += 1

        if (counter == third_octect):  # safety net for if the third octet = the counter it should not, and we add 1
            counter += 1

    while counter < end_ip: # since the out of scope ips should not exceed 255, so it would not be 256 or above we need to keep going until we hit the end_ip whatever it may be depending on the cidr
        if ((counter + 128) in cdr_17):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/17")
            # print(first_2_octects + str(counter) + ".0/17")
            counter += 128
        elif ((counter + 64) in cdr_18):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/18")
            # print(first_2_octects + str(counter) + ".0/18")
            counter += 64
        elif ((counter + 32) in cdr_19):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/19")
            # print(first_2_octects + str(counter) + ".0/19")
            counter += 32
        elif ((counter + 16) in cdr_20):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/20")
            # print(first_2_octects + str(counter) + ".0/20")
            counter += 16
        elif ((counter + 8) in cdr_21):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/21")
            # print(first_2_octects + str(counter) + ".0/21")
            counter = counter + 8
        elif ((counter + 4) in cdr_22):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/22")
            # print(first_2_octects + str(counter) + ".0/22")
            counter += 4
        elif ((counter + 2) in cdr_23):
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/23")
            # print(first_2_octects + str(counter) + ".0/23")
            counter += 2
        else:
            if (first_2_octects + str(counter) + ".0/24") not in out_of_scope_data:
                ips_in_scope.append(first_2_octects + str(counter) + ".0/24")
            # print(first_2_octects + str(counter) + ".0/24")
            counter += 1

def main():
    # this is all to check your input
    if (str(sys.argv[1]).find("-h") != -1 or str(sys.argv[1]).find("-help") != -1): # see if the user is looking for the help file
        print("")
        print("Usage: python3 cidr-autosolve.py IPRange/cidr \"excluded ips seperated by commas\"")
        print("")
        print("Argument".ljust(40), "Description")
        print("IPRange/cidr".ljust(40), "This is the entire subnet range of IPs that are in the environment")
        print("excluded ips seperated by commas".ljust(40), "Self explanitory")
        quit()
    elif (re.search('[a-zA-Z]', sys.argv[1]) or re.search('[a-zA-Z]', sys.argv[2])): # did they put a letter in the ip
        print("Error: Invalid arguments. Try running with -help instead")
        quit()

    if (len(sys.argv) < 3): # did the user give us all the arguments we need
        print("Error: Not enough arguments. Try running with -help instead")
        quit()
    
    #push your input into variables
    scope_data = str(sys.argv[1]) # pass the first argument (supposed to be the scope range) to scope_data
    out_of_scope_data = (str(sys.argv[2]).replace(" ", "")).split(",") # jankey way to take "ip1, ip2" remove the space and split it into the array
    
    #do stuff
    idx_of_2nd_per = scope_data.find(".", scope_data.find(".") + 1)  # this variable holds the index value of the second period of the ip so 192.168.0.0 would return and index of 7
    first_2_octects = scope_data[:idx_of_2nd_per + 1]  # first_2_octects will be the var that holds eg 192.168. (yes it includes the period after 168)

    # counting logic now
    # the counter variable is what would be the third octet
    third_octect = scope_data[idx_of_2nd_per + 1:]  # do this here in case you need to start with a nonzero number
    third_octect = int(third_octect[:third_octect.find('.')])  # do this here in case you need to start with a nonzero number
    counter = int(third_octect)

    if (scope_data.find('/16') != -1): # divisibles of 256
        # if it is a /16 we need to get the first 2 octects seperated
        # also if it is a /16 we have the range of 192.168.0.0 - 192.168.255.255 potentially in scope
        end_ip = 256 # end_ip will be the last ip so if we start with 192.168.15.0 we should end at 192.168.127.255 for the scope
        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/17') != -1): # divisibles of 128
        # if it is a /17 we need to get the first 2 octects seperated
        # also if it is a /17 we have the range of 192.168.0.0 - 192.168.127.255 or 192.168.128.0 - 192.168.255.255 potentially in scope
        # here we need to check if the starting ip is before or after 128
        if (counter >= 128):
            end_ip = 256 # end_ip will be the last ip so if we start with 192.168.15.0 we should end at 192.168.127.255 for the scope
        else:
            end_ip = 128

        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/18') != -1): # divisibles of 64
        # if it is a /18 we need to get the first 2 octects seperated
        # also if it is a /18 we have the range of 192.168.0.0 - 192.168.63.255 or 192.168.64.0 - 192.168.127.255 until 192.168.255.255 potentially in scope
        # here we need to check the starting ip to find the end
        end_ip = 0
        for ip_int in cdr_18:
            if (counter < ip_int):
                end_ip = ip_int
                break
        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/19') != -1): # divisibles of 32
        # if it is a /19 we need to get the first 2 octects seperated
        # also if it is a /19 we have the range of 192.168.0.0 - 192.168.31.255 or 192.168.32.0 - 192.168.63.255 until 192.168.255.255 potentially in scope
        # here we need to check the starting ip to find the end
        end_ip = 0
        for ip_int in cdr_19:
            if (counter < ip_int):
                end_ip = ip_int
                break
        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/20') != -1): # divisibles of 16
        # here we need to check the starting ip to find the end
        end_ip = 0
        for ip_int in cdr_20:
            if (counter < ip_int):
                end_ip = ip_int
                break

        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/21') != -1): # divisibles of 8
        # here we need to check the starting ip to find the end
        end_ip = 0
        for ip_int in cdr_21:
            if (counter < ip_int):
                end_ip = ip_int
                break
        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/22') != -1): # divisibles of 4
        # here we need to check the starting ip to find the end
        end_ip = 0
        for ip_int in cdr_22:
            if (counter < ip_int):
                end_ip = ip_int
                break

        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    elif (scope_data.find('/23') != -1): # divisibles of 2
        # here we need to check the starting ip to find the end
        end_ip = 0
        for ip_int in cdr_23:
            if (counter < ip_int):
                end_ip = ip_int
                break

        do_logic(idx_of_2nd_per, first_2_octects, counter, end_ip, out_of_scope_data)

    for item in ips_in_scope:
        print(item)


if __name__ == '__main__':
    main()
