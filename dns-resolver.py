
import sys
import time
import dns.query, dns.message
rootlist = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

def makeQuery(website, wtype) :
  query = dns.message.make_query(website, wtype)
  return query

def queryUdp (query, server):
  ans = dns.query.udp (query, server)
  return ans

flag = 0
website, wtype = "", ""


def run ():
  global website, wtype
  website, wtype = sys.argv[1], sys.argv[2]
  print("Question Section")
  print(website + " IN " + wtype)
  print("Answer Section")
  answer = resolve(website, wtype)
  print(website + " IN " + wtype + " " + str(answer))
  print("Query time: %s ms" % ((time.time() - startTime) * 1000))
  print("WHEN: " + str(time.ctime()))
  print("MSG SIZE received: " + str(sys.getsizeof(answer)))

def resolve(website, wtype):
  query = makeQuery(website, wtype)
  # return(getAnswer(query, rootlist[0], wtype))

  for server in rootlist:
    if (flag == 1):
      break
    else:
      return(getAnswer(query, server, wtype))
      


def getAnswer(query, server, wtype):
    response = queryUdp(query, server)

    if (len(response.answer) > 0):
    
        if 'CNAME' in response.answer[0].to_text() :
            # print("Checking CNAME")
            return(resolve(response.answer[0][0].to_text(), wtype))
        else:
            # print("Checking ELSE CNAME")
            flag = 1
            return(response.answer[0])         

    elif (len(response.additional) > 0):
    
        for a in response.additional:
            try:          
                return(getAnswer(query, a[0].to_text(),wtype))
            except:
                continue

    elif (len(response.authority) > 0):
        if (response.authority[0].rdtype == dns.rdatatype.SOA):
            if 'WWW' in website[:3] or 'www' in website[:3]:
                print(response.authority[0])

            else:
                query = makeQuery(website, wtype)
                getAnswer(query, server, wtype)


        else:
            for a in response.authority:
                resolve(a[0].to_text(), wtype)

                # response.authority[0]
          

if __name__ == "__main__":
  startTime = time.time()
  run()

