#!/usr/bin/env python
# coding: utf-8

# In[9]:


from Web_Attack_Predictor import *


# In[10]:


print(type(DT), DT, type(SVC), SVC, type(RF), RF)


# In[122]:


# d = {'col1': [1, 4, 3, 4, 5], 'col2': [4, 5, 6, 7, 8], 'col3': [7, 8, 9, 0, 1]}
# df = pd.DataFrame(data=d)
# print("Original DataFrame")
# print(df)
# print('After add one row:')
# df2 = {'col1': 10, 'col2': 11, 'col3': 12}
# df = df.append(df2, ignore_index=True)
# print(df)


# In[139]:


# t_payload = pd.read_csv('data/payloads.csv', index_col='index')
# t_x = create_features(pd.DataFrame(t_payload['payload'][:]))


# In[155]:
def init():
    d = {'payload': [ ]}
    df = pd.DataFrame(data=d)
    print("Original DataFrame")
    display(df)


def create_payload(df, txt_data):
    print('After add one row:')
    df2 = {'payload': txt_data}
    df = df.append(df2, ignore_index=True)  # df 需要重新赋值给它本身
    display(df)
    return df

# df = create_payload(df, '? or 1=1 --')
# df = create_payload(df, 'zyx213416')
# df = create_payload(df, '\' and 1=0) union all')
# df = create_payload(df, '\' and 1 in (select var from temp)--')
# df = create_payload(df, '" or isNULL(1/0) /*')

def predictor1(input_raw):
    d1 = {'payload': [ ]}
    df1 = pd.DataFrame(data=d1)
    print("Original DataFrame")
    display(df1)
    df1 = create_payload(df1, input_raw)
    df1_x= create_features(df1[:])
    # display(df_x.head())
    return DT.predict(df1_x.tail(1))[0]

def predictor2(input_raw):
    d2 = {'payload': [ ]}
    df2 = pd.DataFrame(data=d2)
    print("Original DataFrame")
    display(df2)
    df2 = create_payload(df2, input_raw)
    df2_x = create_features(df2[:])
    # display(df_x.head())
    return SVC.predict(df2_x.tail(1))[0]

def predictor3(input_raw):
    d3 = {'payload': [ ]}
    df3 = pd.DataFrame(data=d3)
    print("Original DataFrame")
    display(df3)
    df3 = create_payload(df3, input_raw)
    df3_x = create_features(df3[:])
    # display(df_x.head())
    return RF.predict(df3_x.tail(1))[0]

# In[156]:


# df_x = create_features(df[:])


# In[158]:


# display(df_x.head())


# In[161]:


# DT.predict(df_x.head())


# In[162]:


# SVC.predict(df_x.head())


# In[163]:


# RF.predict(df_x.head())


# In[160]:


# for i in range(1,6):
#     display(t_x.tail(i))
#     print( DT.predict(t_x.tail(i)) )


# In[ ]:




