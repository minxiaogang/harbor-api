
import random

def passsword_code():
  all_char = '23456789qazwsxedcrfvtgbyhnujmikpQAZWSXEDCRFVTGBYHNUJMLKP'
  index = len(all_char)
  code = ''
  for n in range(10):
    num1 = random.randint(0,index)
    num = num1 - 1
    code += all_char[num]
  return code
print(passsword_code())
