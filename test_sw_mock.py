try:
    from seleniumwire import webdriver
    print(dir(webdriver.request.Request))
except Exception as e:
    print(e)
