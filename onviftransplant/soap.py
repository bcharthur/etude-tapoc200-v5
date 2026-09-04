SOAP_ENV='http://www.w3.org/2003/05/soap-envelope'
DEVICE_WSDL='http://www.onvif.org/ver10/device/wsdl'
ANALYTICS_WSDL='http://www.onvif.org/ver20/analytics/wsdl'

def baseline_get_time():
    return f"""<?xml version="1.0" encoding="UTF-8"?>\n<soap:Envelope xmlns:soap="{SOAP_ENV}"><soap:Body><tds:GetSystemDateAndTime xmlns:tds="{DEVICE_WSDL}"/></soap:Body></soap:Envelope>""".encode()

def prefix_case(length):
    if length<1:raise ValueError('prefix length must be >=1')
    prefix='a'*length
    return f"""<?xml version="1.0" encoding="UTF-8"?>\n<soap:Envelope xmlns:soap="{SOAP_ENV}"><soap:Body><{prefix}:GetSystemDateAndTime xmlns:{prefix}="{DEVICE_WSDL}"/></soap:Body></soap:Envelope>""".encode()

def element_case(count,value_len=100):
    if count<1:raise ValueError('count must be >=1')
    value='X'*value_len
    params=''.join(f'<SimpleItem Name="Param{i}" Value="{value}"/>' for i in range(count))
    return f"""<?xml version="1.0" encoding="UTF-8"?>\n<soap:Envelope xmlns:soap="{SOAP_ENV}"><soap:Body><CreateRules xmlns="{ANALYTICS_WSDL}"><ConfigurationToken>rootlab-transplant</ConfigurationToken><Rule><Name>RootLabRule</Name><Type>tt:CellMotionDetector</Type><Parameters>{params}</Parameters></Rule></CreateRules></soap:Body></soap:Envelope>""".encode()

CONSERVATIVE_PREFIX=[1,8,16,32,64,96,128,192,256,384,512,768,1024,1536,2048]
EXTENDED_PREFIX=CONSERVATIVE_PREFIX+[3072,4096,6144,8192]
CONSERVATIVE_ELEMENTS=[1,4,16,64,128,256,512,1024,2048]
EXTENDED_ELEMENTS=CONSERVATIVE_ELEMENTS+[4096,8192,16384]
