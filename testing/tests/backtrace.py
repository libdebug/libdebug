from libdebug import debugger

d = debugger('./backtrace')

d.start()

def check_main(d,b):
    print('main')
    print(d.backtrace())

def check_function1(d,b):
    print('function1')
    print(d.backtrace())

def check_function2(d,b):
    print('function2')
    print(d.backtrace())

def check_function3(d,b):
    print('function3')
    print(d.backtrace())

def check_function4(d,b):
    print('function4')
    print(d.backtrace())

def check_function5(d,b):
    print('function5')
    print(d.backtrace())

def check_function6(d,b):
    print('function6')
    print(d.backtrace())

d.b('main', check_main)
d.b('function1', check_function1)
d.b('function2', check_function2)
d.b('function3', check_function3)
d.b('function4', check_function4)
d.b('function5', check_function5)
d.b('function6', check_function6)

d.cont()