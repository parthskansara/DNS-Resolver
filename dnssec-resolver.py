import dns.name
import dns.query
import dns.resolver
import sys
import time

rootlist = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
           "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]

rootlist_keys = [
    '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29 euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v 58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8 g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37 NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/E fucp2gaDX6RS6CXpoY68LsvPVjR0ZSwz z1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgu l0sGIcGOYl7OyQdXfZ57relSQageu+ip AdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1 dfwhYB4N7knNnulqQxA+Uk1ihz0=',
    '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=']

rootlist_keys = set(rootlist_keys)

def validateRootServer(response):
    kskList = list()
    X = response.answer[0]
    for i in range(0,3):
        if '257' in str(X[i]):
            kskList.append(str(X[i]))

    flag = 0
    for key in rootlist_keys:
        # KSK Validation
        if key in kskList:
            flag = 1
            break
    if flag == 0:
        return 'DNSSec verification failed'

def validateDS (response, iterResponse):
    if len(response.authority) == 3 and len(iterResponse.answer) != 0:
        #1 -- RRSet 2 -- RRsig 3 --DNSKeys RRset
        #response 1 = RRSet
        #response 2 = RRsig
        try:
            (dns.dnssec.validate(response.authority[1], response.authority[2], {name: iterResponse.answer[0]}))
        except:
            return 'Error in Resolution'
    else:
        return 'DNSSEC not supported'


def getZones(hostname, passCounter):
    period = hostname.strip('.').split('.')
    q = ''
    if passCounter == 0:
        q = '.'
    else:
        q = ".".join(period[-passCounter:])
        q += "."

    return q

# def dsValidation(response, iterResponse, prevDSrecord):
    



def resolve(hostname,response):
    #taken from 
    listOfServers = rootlist
    prevDSrecord = []
    counter = 3
    passCounter = 0
    while len(listOfServers) >= 1 and counter >= 0:
        counter -= 1
        
        q = getZones(hostname, passCounter)      
        passCounter += 1

        for server in listOfServers:
                server = str(server)
                data = server.split(' ')
            #try:
                query = dns.message.make_query(hostname,dns.rdatatype.A,want_dnssec=True)
                if len(data[-1]) > 16:
                    continue

                response = dns.query.tcp(query,data[-1])
                listOfServers = response.additional
                

                iterQuery = dns.message.make_query(q,dns.rdatatype.DNSKEY,want_dnssec=True)
                iterResponse = dns.query.tcp(iterQuery,data[-1])

                if q != '.':
                    name = dns.name.from_text(q)
                    if len(response.answer) is not None:
                        validateDS (response, iterResponse)                       
                    else:
                        pass

                else:
                    validateRootServer(iterResponse)

                if q != '.':
                    if len(iterResponse.answer) != 0:
                        flag = 0
                        for i in range(0,len(iterResponse.answer[0])):
                            # Create DS record from DNSKey response for SHA1 and SHA256 algorithms
                            dnssecKey = iterResponse.answer[0][i]

                            if '257' in str(dnssecKey):
                                DSSHA256 = str(dns.dnssec.make_ds(name=q,key=dnssecKey,algorithm='SHA256')).split(' ')
                                DSSHA1 = str(dns.dnssec.make_ds(name=q,key=dnssecKey,algorithm='SHA1')).split(' ')
                                prevDSrecord = str(prevDSrecord)
                                partprevDSrecord = prevDSrecord.split(' ')
                                if DSSHA256[-1] != partprevDSrecord[-1] and DSSHA1[-1] != partprevDSrecord[-1]:
                                    # pass
                                    continue
                                else:
                                    flag = 1
                                    break

                        if flag != 0:
                            if len(response.answer) > 0 and str(response.answer[0]).split(" ")[3] == "A":
                                return [str(response.answer[0]).split(" ")[4]]
                        else:
                            return 'DNSSec verification failed'
                        
                            
                    else:
                        return 'DNSSEC not supported'
                else:
                    pass

                #After validation, store the current DS record for next validation
                if len(response.authority) > 0:
                    prevDSrecord = response.authority[1]
                else:
                    return 'DNSSEC not supported'

                name = dns.name.from_text(q)
                if len(iterResponse.answer) == 2:
                    # 1 -- RRset 2 -- RRsig 3 -- RRset
                    #DNSKEYS VALIDATION

                    try:
                        dns.dnssec.validate(iterResponse.answer[0], iterResponse.answer[1], {name: iterResponse.answer[0]})
                    except dns.dnssec.ValidationFailure:
                        return 'DNSSec verification failed'
                    else:
                        pass
                else:
                    return 'DNSSEC not supported'
                break
            #except:
                # print 'Server not responding. Trying the next server...'

        if len(response.additional) > 0:
            continue

        elif len(response.answer) > 0:
            
            data = str(response.answer[0]).split(' ')
            if data[3] == 'CNAME':
                return resolve(data[-1],response)
            else:
                return response.answer        

        else:
            ans = str(response.authority[0])
            data = ans.split(' ')
            listOfServers = resolve(data[-1],response)

def run():
    global question
    question = sys.argv[1]

    data = question.split('.')
    if data[0] == 'www':
        query = ''
        for d in data[1:]:
            query = query + d + '.'
    else:
        query = question
    try:
        response = resolve(query,'')

        if type(response) == str:

            print (response)
        else:
            print (response)
    except:
        print ('Error in Resolution')


if __name__ == '__main__':
    run()

    
