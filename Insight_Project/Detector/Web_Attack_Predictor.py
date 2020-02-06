#!/usr/bin/env python
# coding: utf-8

# # Part1 -- Data Prepare
# Source Data https://github.com/foospidy/payloads

# In[1]:


import numpy as np
import pandas as pd
from IPython.display import display


# In[2]:


def from_txt_to_dataframe(src_file,is_malicious,injection_type):
    
    #read file
    payloads_txt = open('data/{}.txt'.format(src_file),'r',encoding='UTF-8').readlines()
    
    #create dataframe
    
    payloads = pd.DataFrame(payloads_txt,columns=['payload'])
    payloads['is_malicious'] = [is_malicious]*len(payloads)
    payloads['injection_type'] = [injection_type]*len(payloads)
    
    print('First 5 lines of ' + injection_type)
    display(payloads.head(10)) # default is 5
    
    return payloads


# In[3]:


# payloads = pd.DataFrame(columns=['payload','is_malicious','injection_type'])
# payloads = payloads.append(from_txt_to_dataframe('SQLCollection',1,'SQL'))


# In[4]:


# payloads = payloads.append(from_txt_to_dataframe('XSSCollection',1,'XSS'))


# In[5]:


# payloads = payloads.append(from_txt_to_dataframe('ShellCollection',1,'SHELL'))


# In[6]:


# payloads = payloads.append(from_txt_to_dataframe('non-maliciousCollection',0,'LEGAL'))


# In[7]:


payloads = pd.read_csv("/Users/user/Downloads/git_projects/back_end_projects/Insight_Project/Detector/data/payloads.csv",index_col='index')
display(payloads.head(20))


# # Part 2 -- Features Extract
# 1.length of payload
# 2.number of non-printable characters in payload
# 3.number of punctuation characters in payload
# 4.the minimum byte value of payload
# 5.the maximum byte value of payload
# 6.the mean byte value of payload
# 7.the standard deviation of payload byte values
# 8.number of distinct bytes in payload
# 9.number of SQL keywords in payload
# 10.number of javascript keywords in payload
# In[8]:


print(type(payloads), payloads.shape)
display(payloads.head(50))


# In[9]:


def create_length_feature(payloads):
    payloads['length'] = [len(str(r)) for r in payloads['payload']]
    return payloads


# In[10]:


payloads = create_length_feature(payloads)
display(payloads.head(50))


# In[11]:


print(payloads['length'].name)
print(payloads['length'].describe())
print(payloads['length'].describe().name)
print(payloads['length'].describe().dtype)
print(payloads['length'].describe().mean)
print(payloads['length'].describe()[7])


# In[12]:


import string
def create_non_printable_characters_feature(payloads):
    payloads['non_printable_chars'] = [len([1 for c in str(r) if c not in string.printable]) for r in payloads['payload']]
    return payloads


# In[13]:


print(string.printable, len(string.printable), string.printable[:62], string.printable[62:100])
# for i, c in enumerate(string.printable[62:100]): print(i,c)
payloads = create_non_printable_characters_feature(payloads)
display(payloads.head(50))


# In[14]:


print(payloads['non_printable_chars'].name)
print(payloads['non_printable_chars'].describe())
print(payloads['non_printable_chars'].describe().name)
print(payloads['non_printable_chars'].describe().dtype)
print(payloads['non_printable_chars'].describe().mean)
print(payloads['non_printable_chars'].describe()[7])


# In[15]:


def create_punctuation_chars_feature(payloads):
    payloads['punctuation'] = [ len([1 for c in str(r) if c in string.punctuation]) for r in payloads['payload']]
    return payloads


# In[16]:


print(string.punctuation)
payloads = create_punctuation_chars_feature(payloads)
display(payloads.head(50))


# In[17]:


print(payloads['punctuation'].name)
print(payloads['punctuation'].describe())
print(payloads['punctuation'].describe().name)
print(payloads['punctuation'].describe().dtype)
print(payloads['punctuation'].describe().mean)
print(payloads['punctuation'].describe()[7])


# In[18]:


# for r in payloads['payload']: print(r, min(str(r)))


# In[19]:


def create_min_byte_value_feature(payloads):
    payloads['min-byte'] = [ min(bytearray(str(r), 'utf-8')) for r in payloads['payload']]
    return payloads


# In[20]:


payloads = create_min_byte_value_feature(payloads)
display(payloads.head(50))


# In[21]:


print(payloads['min-byte'].name)
print(payloads['min-byte'].describe())
print(payloads['min-byte'].describe().name)
print(payloads['min-byte'].describe().dtype)
print(payloads['min-byte'].describe().mean)
print(payloads['min-byte'].describe()[7])


# In[22]:


def create_max_byte_value_feature(payloads):
    payloads['max-byte'] = [ max(bytearray(str(r), 'utf-8')) for r in payloads['payload'] ]
    return payloads


# In[23]:


payloads = create_max_byte_value_feature(payloads)
display(payloads.head(50))


# In[24]:


print(payloads['max-byte'].name)
print(payloads['max-byte'].describe())
print(payloads['max-byte'].describe().name)
print(payloads['max-byte'].describe().dtype)
print(payloads['max-byte'].describe().mean)
print(payloads['max-byte'].describe()[7])


# In[25]:


def create_mean_byte_value_feature(payloads):
    payloads['mean-byte'] = [ sum(bytearray(str(r), 'utf-8'))/ len(bytearray(str(r), 'utf-8')) for r in payloads['payload']]
    return payloads


# In[26]:


payloads = create_mean_byte_value_feature(payloads)
display(payloads.head(50))


# In[27]:


print(payloads['mean-byte'].name)
print(payloads['mean-byte'].describe())
print(payloads['mean-byte'].describe().name)
print(payloads['mean-byte'].describe().dtype)
print(payloads['mean-byte'].describe().mean)
print(payloads['mean-byte'].describe()[7])


# In[28]:


def create_standard_deviation_byte_value_feature(payloads):
    payloads['standard-deviation-byte'] = [ np.std(bytearray(str(r), 'utf-8')) for r in payloads['payload']]
    return payloads


# In[29]:


payloads = create_standard_deviation_byte_value_feature(payloads)
display(payloads.head(50))


# In[30]:


print(payloads['standard-deviation-byte'].name)
print(payloads['standard-deviation-byte'].describe())
print(payloads['standard-deviation-byte'].describe().name)
print(payloads['standard-deviation-byte'].describe().dtype)
print(payloads['standard-deviation-byte'].describe().mean)
print(payloads['standard-deviation-byte'].describe()[7])


# In[31]:


def create_distinct_byte_value_feature(payloads):
    payloads['distinct-byte'] = [ len(set(str(r))) for r in payloads['payload']]
    return payloads


# In[32]:


payloads = create_distinct_byte_value_feature(payloads)
display(payloads.head(50))


# In[33]:


print(payloads['distinct-byte'].name)
print(payloads['distinct-byte'].describe())
print(payloads['distinct-byte'].describe().name)
print(payloads['distinct-byte'].describe().dtype)
print(payloads['distinct-byte'].describe().mean)
print(payloads['distinct-byte'].describe()[7])


# In[34]:


sql_keywords = pd.read_csv('/Users/user/Downloads/git_projects/back_end_projects/Insight_Project/Detector/data/SQLKeywords.txt', index_col=False)
def create_sql_keywords_feature(payloads):
    payloads['sql-keywords'] = [ len([1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in str(row).lower()]) for row in payloads['payload']]
    return payloads


# In[35]:


create_sql_keywords_feature(payloads)
display(payloads.head(50))


# In[36]:


# js_keywords = pd.read_csv('/Users/user/Downloads/git_projects/back_end_projects/Insight_Project/Detector/data/JavascriptKeywords.txt', index_col=False)
# def create_javascript_keywords_feature(payloads):
#     payloads['js-keywords'] = [len([1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in str(row).lower()]) for row in payloads['payload']]
#     return payloads


# In[37]:


# create_javascript_keywords_feature(payloads)
# display(payloads.head(50))


# In[38]:


# payloads.to_csv("data/processed_payloads.csv", encoding='utf-8', index = True, header=True)


# In[39]:


# login_keywords = pd.read_csv('data/darkweb2017-top10000.txt', index_col=False)
# # print(login_keywords, type(login_keywords), login_keywords.shape)
# def create_web_login_keywords_feature(payloads):
#     payloads['login_keywords'] = [len([1 for keyword in login_keywords['Keyword'] if str(keyword).lower() in str(row).lower()]) for row in payloads['payload']]
#     return payloads


# In[40]:


# create_web_login_keywords_feature(payloads)
# display(payloads.head(50))


# In[41]:


# name_keywords = pd.read_csv('data/names.txt', index_col=False)
# def create_name_keywords_feature(payloads):
#     payloads['name-keywords'] = [len([1 for keyword in name_keywords['Keyword'] if str(keyword).lower() in str(row).lower()]) for row in payloads['payload']]
#     return payloads


# In[42]:


# create_name_keywords_feature(payloads)
# display(payloads.head(50))


# In[43]:


def create_features(payloads):
    features = create_length_feature(payloads)
    features = create_non_printable_characters_feature(features)
    features = create_punctuation_chars_feature(features)
    features = create_max_byte_value_feature(features)
    features = create_min_byte_value_feature(features)
    features = create_mean_byte_value_feature(features)
    features = create_standard_deviation_byte_value_feature(features)
    features = create_distinct_byte_value_feature(features)
    features = create_sql_keywords_feature(features)
    del features['payload']
    return features


# In[44]:


# def create_powerful_features(payloads):
#     features = create_web_login_keywords_feature(payloads)
#     features = create_name_keywords_feature(features)
#     del features['payload']
#     return features


# In[45]:


Y = payloads['is_malicious']
X = create_features(pd.DataFrame(payloads['payload'][:]))


# In[46]:


display(X.head(50))


# In[47]:


display(Y.head(50))


# In[48]:


print(X.shape, Y.shape)


# # Part 3 -- Model Selection
# Classifiers tested using our custom feature space:
# * AdaBoost
# * SGD classifier
# * MultiLayerPerceptron classifier
# * Logistic Regression
# * Support Vector Machine
# * Random forest
# * Decision Tree
# * Multinomial Naive Bayes

# Extra Bonus Part -- After figuring out how to deal with N-grams features:
# Classifiers tested using bag-of-words feature spaces:
# * MultiLayerPerceptron classifier
# * Logistic Regression
# * Support Vector Machine
# * Random forest
# * Multinomial Naive Bayes 
# In[49]:


from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import AdaBoostClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle


# In[50]:


def create_classifier(type):
    if type == 'AdaBoost': clf = AdaBoostClassifier(n_estimators=100)
    elif type == "LogisticRegressionL1": clf = LogisticRegression(penalty='l1', tol=0.0001, C=1.0) 
    elif type == "LogisticRegressionL2": clf = LogisticRegression(penalty='l2', tol=0.0001, C=1.0) 
    elif type == "SGD": clf = SGDClassifier(loss="log", penalty="l2")
    elif type == "MLPClassifier": clf = MLPClassifier(activation='relu', solver='adam', early_stopping=False, verbose=True)
    elif type == 'SVC':  clf = SVC()
    elif type == 'RandomForest': clf = RandomForestClassifier(max_depth=None, min_samples_split=2, random_state=0)
    elif type == 'DecisionTreeClassifier': clf = DecisionTreeClassifier()
    elif type == 'MultinomialNB': clf = MultinomialNB()
    else: clf = LogisticRegression(penalty='l2', tol=0.0001, C=1.0)
    return clf 


# In[51]:


AdaBoost = create_classifier("AdaBoost")
LR1 = create_classifier("LogisticRegressionL1")
LR2 = create_classifier("LogisticRegressionL2")
SGD = create_classifier("SGD")
MLP = create_classifier("MLPClassifier")
SVC = create_classifier("SVC")
RF = create_classifier("RandomForest")
DT = create_classifier("DecisionTreeClassifier")
MNB = create_classifier("MultinomialNB")


# In[52]:


shuffle(X)
shuffle(Y)
x_train, x_test, y_train, y_test = train_test_split(X, Y, train_size=0.75,test_size=0.25)


# In[53]:


print(x_train.shape, y_train.shape)
print(x_test.shape, y_test.shape)


# In[54]:


def tn(y_true, y_pred): return confusion_matrix(y_true, y_pred)[0, 0]
def fp(y_true, y_pred): return confusion_matrix(y_true, y_pred)[0, 1]
def fn(y_true, y_pred): return confusion_matrix(y_true, y_pred)[1, 0]
def tp(y_true, y_pred): return confusion_matrix(y_true, y_pred)[1, 1]


# # Part 4 -- Model Evalution

# In[55]:


import matplotlib.pyplot as plt
from sklearn.model_selection import learning_curve
from sklearn import metrics
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score
from sklearn.metrics import r2_score
from sklearn.metrics import hamming_loss
from sklearn.metrics import log_loss
from sklearn.metrics import zero_one_loss
from sklearn.metrics import mean_absolute_error
from sklearn.metrics import mean_squared_error
from sklearn.metrics import mean_squared_log_error
from sklearn.metrics import median_absolute_error
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import auc
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score


# ## 4.1 --  AdaBoost

# In[56]:


ada_x_train, ada_y_train = x_train[:], y_train[:]
AdaBoost.fit(ada_x_train, ada_y_train)
# AdaBoost.fit(x_train[:],y_train[:], verbose = 1)


# In[57]:


Ada_x_test =  x_test[:]
Ada_y_test = AdaBoost.predict(Ada_x_test)
print(Ada_y_test.shape)


# In[58]:


train_sizes, train_scores, test_scores = learning_curve(AdaBoost, ada_x_train, ada_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("AdaBoost Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[59]:


print(confusion_matrix(y_test, Ada_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, Ada_y_test).ravel()
print(tn, fp, fn, tp)


# In[60]:


print(classification_report(y_test, Ada_y_test))


# In[61]:


print('hamming loss: ', hamming_loss(y_test, Ada_y_test))
print('log loss: ', log_loss(y_test, Ada_y_test))
print('zero one loss: ', zero_one_loss(y_test, Ada_y_test))


# In[62]:


print('mean absolute error: ',  mean_absolute_error(y_test, Ada_y_test) )
print('mean squared error: ', mean_squared_error(y_test, Ada_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, Ada_y_test) )
print('median absolute error: ', median_absolute_error(y_test, Ada_y_test) )


# In[63]:


print( 'accuracy score: ', accuracy_score(y_test, Ada_y_test) )
precision_score = metrics.precision_score(y_test, Ada_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, Ada_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, Ada_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, Ada_y_test)
print('auc_score: ', auc_score)


# In[64]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, Ada_y_test))
pre, rec, t = precision_recall_curve(y_test, Ada_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, Ada_y_test))
fpr, tpr, thresholds = roc_curve(y_test, Ada_y_test)
print(fpr, tpr, thresholds)


# In[65]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('AdaBoost PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[66]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('AdaBoost Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.2 --  Logistic Regression L1

# In[67]:


LR1_x_train, LR1_y_train = x_train[:], y_train[:]
LR1.fit(LR1_x_train, LR1_y_train)


# In[68]:


LR1_x_test =  x_test[:]
LR1_y_test = LR1.predict(LR1_x_test)
print(LR1_y_test.shape)


# In[69]:


train_sizes, train_scores, test_scores = learning_curve(LR1, LR1_x_train, LR1_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("LR1 Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[70]:


print(confusion_matrix(y_test, LR1_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, LR1_y_test).ravel()
print(tn, fp, fn, tp)


# In[71]:


print(classification_report(y_test, LR1_y_test))


# In[72]:


print('hamming loss: ', hamming_loss(y_test, LR1_y_test))
print('log loss: ', log_loss(y_test, LR1_y_test))
print('zero one loss: ', zero_one_loss(y_test, LR1_y_test))


# In[73]:


print('mean absolute error: ',  mean_absolute_error(y_test, LR1_y_test) )
print('mean squared error: ', mean_squared_error(y_test, LR1_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, LR1_y_test) )
print('median absolute error: ', median_absolute_error(y_test, LR1_y_test) )


# In[74]:


print( 'accuracy score: ', accuracy_score(y_test, LR1_y_test) )
precision_score = metrics.precision_score(y_test, LR1_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, LR1_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, LR1_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, LR1_y_test)
print('auc_score: ', auc_score)


# In[75]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, LR1_y_test))
pre, rec, t = precision_recall_curve(y_test, LR1_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, LR1_y_test))
fpr, tpr, thresholds = roc_curve(y_test, LR1_y_test)
print(fpr, tpr, thresholds)


# In[76]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('LR1 PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[77]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('LR1 Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.3 --  LogisticRegressionL2

# In[78]:


LR2_x_train, LR2_y_train = x_train[:], y_train[:]
LR2.fit(LR2_x_train, LR2_y_train)


# In[79]:


LR2_x_test =  x_test[:]
LR2_y_test = LR2.predict(LR2_x_test)
print(LR2_y_test.shape)


# In[80]:


train_sizes, train_scores, test_scores = learning_curve(LR2, LR2_x_train, LR2_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("LR2 Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[81]:


print(confusion_matrix(y_test, LR2_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, LR2_y_test).ravel()
print(tn, fp, fn, tp)


# In[82]:


print(classification_report(y_test, LR2_y_test))


# In[83]:


print('hamming loss: ', hamming_loss(y_test, LR2_y_test))
print('log loss: ', log_loss(y_test, LR2_y_test))
print('zero one loss: ', zero_one_loss(y_test, LR2_y_test))


# In[84]:


print('mean absolute error: ',  mean_absolute_error(y_test, LR2_y_test) )
print('mean squared error: ', mean_squared_error(y_test, LR2_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, LR2_y_test) )
print('median absolute error: ', median_absolute_error(y_test, LR2_y_test) )


# In[85]:


print( 'accuracy score: ', accuracy_score(y_test, LR2_y_test) )
precision_score = metrics.precision_score(y_test, LR2_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, LR2_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, LR2_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, LR2_y_test)
print('auc_score: ', auc_score)


# In[86]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, LR2_y_test))
pre, rec, t = precision_recall_curve(y_test, LR2_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, LR2_y_test))
fpr, tpr, thresholds = roc_curve(y_test, LR2_y_test)
print(fpr, tpr, thresholds)


# In[87]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('LR2 PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[88]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('LR2 Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.4 --  SGD

# In[89]:


SGD_x_train, SGD_y_train = x_train[:], y_train[:]
SGD.fit(SGD_x_train, SGD_y_train)


# In[90]:


SGD_x_test =  x_test[:]
SGD_y_test = SGD.predict(SGD_x_test)
print(SGD_y_test.shape)


# In[91]:


train_sizes, train_scores, test_scores = learning_curve(SGD, SGD_x_train, SGD_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("SGD Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[92]:


print(confusion_matrix(y_test, SGD_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, SGD_y_test).ravel()
print(tn, fp, fn, tp)


# In[93]:


print(classification_report(y_test, SGD_y_test))


# In[94]:


print('hamming loss: ', hamming_loss(y_test, SGD_y_test))
print('log loss: ', log_loss(y_test, SGD_y_test))
print('zero one loss: ', zero_one_loss(y_test, SGD_y_test))


# In[95]:


print('mean absolute error: ',  mean_absolute_error(y_test, SGD_y_test) )
print('mean squared error: ', mean_squared_error(y_test, SGD_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, SGD_y_test) )
print('median absolute error: ', median_absolute_error(y_test, SGD_y_test) )


# In[96]:


print( 'accuracy score: ', accuracy_score(y_test, SGD_y_test) )
precision_score = metrics.precision_score(y_test, SGD_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, SGD_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, SGD_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, SGD_y_test)
print('auc_score: ', auc_score)


# In[97]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, SGD_y_test))
pre, rec, t = precision_recall_curve(y_test, SGD_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, SGD_y_test))
fpr, tpr, thresholds = roc_curve(y_test, SGD_y_test)
print(fpr, tpr, thresholds)


# In[98]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('SGD PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[99]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('SGD Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.5 --  MLPClassifier

# In[100]:


MLP_x_train, MLP_y_train = x_train[:], y_train[:]
MLP.fit(MLP_x_train, MLP_y_train)


# In[101]:


MLP_x_test =  x_test[:]
MLP_y_test = MLP.predict(MLP_x_test)
print(MLP_y_test.shape)


# In[102]:


train_sizes, train_scores, test_scores = learning_curve(MLP, MLP_x_train, MLP_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("MLP Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[103]:


print(confusion_matrix(y_test, MLP_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, MLP_y_test).ravel()
print(tn, fp, fn, tp)


# In[104]:


print(classification_report(y_test, MLP_y_test))


# In[105]:


print('hamming loss: ', hamming_loss(y_test, MLP_y_test))
print('log loss: ', log_loss(y_test, MLP_y_test))
print('zero one loss: ', zero_one_loss(y_test, MLP_y_test))


# In[106]:


print('mean absolute error: ',  mean_absolute_error(y_test, MLP_y_test) )
print('mean squared error: ', mean_squared_error(y_test, MLP_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, MLP_y_test) )
print('median absolute error: ', median_absolute_error(y_test, MLP_y_test) )


# In[107]:


print( 'accuracy score: ', accuracy_score(y_test, MLP_y_test) )
precision_score = metrics.precision_score(y_test, MLP_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, MLP_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, MLP_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, MLP_y_test)
print('auc_score: ', auc_score)


# In[108]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, MLP_y_test))
pre, rec, t = precision_recall_curve(y_test, MLP_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, MLP_y_test))
fpr, tpr, thresholds = roc_curve(y_test, MLP_y_test)
print(fpr, tpr, thresholds)


# In[109]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('MLP PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[110]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('MLP Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.6 --  SVC

# In[111]:


SVC_x_train, SVC_y_train = x_train[:], y_train[:]
SVC.fit(SVC_x_train, SVC_y_train)


# In[112]:


SVC_x_test =  x_test[:]
SVC_y_test = SVC.predict(SVC_x_test)
print(SVC_y_test.shape)


# In[113]:


train_sizes, train_scores, test_scores = learning_curve(SVC, SVC_x_train, SVC_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("SVC Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[114]:


print(confusion_matrix(y_test, SVC_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, SVC_y_test).ravel()
print(tn, fp, fn, tp)


# In[115]:


print(classification_report(y_test, SVC_y_test))


# In[116]:


print('hamming loss: ', hamming_loss(y_test, SVC_y_test))
print('log loss: ', log_loss(y_test, SVC_y_test))
print('zero one loss: ', zero_one_loss(y_test, SVC_y_test))


# In[117]:


print('mean absolute error: ',  mean_absolute_error(y_test, SVC_y_test) )
print('mean squared error: ', mean_squared_error(y_test, SVC_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, SVC_y_test) )
print('median absolute error: ', median_absolute_error(y_test, SVC_y_test) )


# In[118]:


print( 'accuracy score: ', accuracy_score(y_test, SVC_y_test) )
precision_score = metrics.precision_score(y_test, SVC_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, SVC_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, SVC_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, SVC_y_test)
print('auc_score: ', auc_score)


# In[119]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, SVC_y_test))
pre, rec, t = precision_recall_curve(y_test, SVC_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, SVC_y_test))
fpr, tpr, thresholds = roc_curve(y_test, SVC_y_test)
print(fpr, tpr, thresholds)


# In[120]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('SVC  PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[121]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('SVC Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.7 --  RandomForest

# In[122]:


RF_x_train, RF_y_train = x_train[:], y_train[:]
RF.fit(RF_x_train, RF_y_train)


# In[123]:


RF_x_test =  x_test[:]
RF_y_test = RF.predict(RF_x_test)
print(RF_y_test.shape)


# In[124]:


train_sizes, train_scores, test_scores = learning_curve(RF, RF_x_train, RF_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("Random Forest Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[125]:


print(confusion_matrix(y_test, RF_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, RF_y_test).ravel()
print(tn, fp, fn, tp)


# In[126]:


print(classification_report(y_test, RF_y_test))


# In[127]:


print('hamming loss: ', hamming_loss(y_test, RF_y_test))
print('log loss: ', log_loss(y_test, RF_y_test))
print('zero one loss: ', zero_one_loss(y_test, RF_y_test))


# In[128]:


print('mean absolute error: ',  mean_absolute_error(y_test, RF_y_test) )
print('mean squared error: ', mean_squared_error(y_test, RF_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, RF_y_test) )
print('median absolute error: ', median_absolute_error(y_test, RF_y_test) )


# In[129]:


print( 'accuracy score: ', accuracy_score(y_test, RF_y_test) )
precision_score = metrics.precision_score(y_test, RF_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, RF_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, RF_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, RF_y_test)
print('auc_score: ', auc_score)


# In[130]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, RF_y_test))
pre, rec, t = precision_recall_curve(y_test, RF_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, RF_y_test))
fpr, tpr, thresholds = roc_curve(y_test, RF_y_test)
print(fpr, tpr, thresholds)


# In[131]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('Random Forest PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[132]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Random Forest Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.8 --  DecisionTreeClassifier

# In[133]:


DT_x_train, DT_y_train = x_train[:], y_train[:]
DT.fit(DT_x_train, DT_y_train)


# In[134]:


DT_x_test =  x_test[:]
DT_y_test = DT.predict(DT_x_test)
print(DT_y_test.shape)


# In[135]:


train_sizes, train_scores, test_scores = learning_curve(DT, DT_x_train, DT_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("Decision Tree Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[136]:


print(confusion_matrix(y_test, DT_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, DT_y_test).ravel()
print(tn, fp, fn, tp)


# In[137]:


print(classification_report(y_test, DT_y_test))


# In[138]:


print('hamming loss: ', hamming_loss(y_test, DT_y_test))
print('log loss: ', log_loss(y_test, DT_y_test))
print('zero one loss: ', zero_one_loss(y_test, DT_y_test))


# In[139]:


print('mean absolute error: ',  mean_absolute_error(y_test, DT_y_test) )
print('mean squared error: ', mean_squared_error(y_test, DT_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, DT_y_test) )
print('median absolute error: ', median_absolute_error(y_test, DT_y_test) )


# In[140]:


print( 'accuracy score: ', accuracy_score(y_test, DT_y_test) )
precision_score = metrics.precision_score(y_test, DT_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, DT_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, DT_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, DT_y_test)
print('auc_score: ', auc_score)


# In[141]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, DT_y_test))
pre, rec, t = precision_recall_curve(y_test, DT_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, DT_y_test))
fpr, tpr, thresholds = roc_curve(y_test, DT_y_test)
print(fpr, tpr, thresholds)


# In[142]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('Decision Tree PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[143]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Decision Tree Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# ## 4.9 --  MultinomialNB

# In[144]:


MNB_x_train, MNB_y_train = x_train[:], y_train[:]
MNB.fit(MNB_x_train, MNB_y_train)


# In[145]:


MNB_x_test =  x_test[:]
MNB_y_test = MNB.predict(MNB_x_test)
print(MNB_y_test.shape)


# In[146]:


train_sizes, train_scores, test_scores = learning_curve(MNB, MNB_x_train, MNB_y_train, cv = 4, scoring='accuracy', n_jobs=-1)

# Create means and standard deviations of training set scores
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)

# Create means and standard deviations of test set scores
test_mean = np.mean(test_scores, axis=1)
test_std = np.std(test_scores, axis=1)

# Draw lines
plt.plot(train_sizes, train_mean, 'o-', color="r",  label="Training score")
plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")

# Draw bands
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color="g")

# Create plot
plt.title("MNB Learning Curve")
plt.xlabel("Training Set Size"), plt.ylabel("Accuracy Score"), plt.legend(loc="best")
plt.tight_layout()
plt.show()


# In[147]:


print(confusion_matrix(y_test, MNB_y_test))
tn, fp, fn, tp = confusion_matrix(y_test, MNB_y_test).ravel()
print(tn, fp, fn, tp)


# In[148]:


print(classification_report(y_test, MNB_y_test))


# In[149]:


print('hamming loss: ', hamming_loss(y_test, MNB_y_test))
print('log loss: ', log_loss(y_test, MNB_y_test))
print('zero one loss: ', zero_one_loss(y_test, MNB_y_test))


# In[150]:


print('mean absolute error: ',  mean_absolute_error(y_test, MNB_y_test) )
print('mean squared error: ', mean_squared_error(y_test, MNB_y_test) )
print('mean squared log error: ',  mean_squared_log_error(y_test, MNB_y_test) )
print('median absolute error: ', median_absolute_error(y_test, MNB_y_test) )


# In[151]:


print( 'accuracy score: ', accuracy_score(y_test, MNB_y_test) )
precision_score = metrics.precision_score(y_test, MNB_y_test)
print('precision score: ' , precision_score )
recall_score = metrics.recall_score(y_test, MNB_y_test)
print('recall score: ' , recall_score)
f1_score = metrics.f1_score(y_test, MNB_y_test) # f1 = (2 * pre * rec) / (pre + rec)
print('F1 score: ' , f1_score)
auc_score = roc_auc_score(y_test, MNB_y_test)
print('auc_score: ', auc_score)


# In[152]:


print('precision_recall_curve: \n', precision_recall_curve(y_test, MNB_y_test))
pre, rec, t = precision_recall_curve(y_test, MNB_y_test)
print(pre, rec, t)
print('roc curve: \n', roc_curve(y_test, MNB_y_test))
fpr, tpr, thresholds = roc_curve(y_test, MNB_y_test)
print(fpr, tpr, thresholds)


# In[153]:


plt.figure()
plt.plot(pre, rec, color ='green', label='PR curve (area = %0.5f)' % f1_score)
plt.plot([0, 1], [0, 1], color ='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('precision')
plt.ylabel('recall')
plt.title('MNB PR curve')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[154]:


plt.figure()
plt.plot(fpr, tpr, color='darkorange', label='ROC curve (area = %0.5f)' % auc_score)
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('MNB Receiver operating characteristic')
plt.legend(loc="lower right")
plt.show()
plt.close() 


# In[ ]:





# In[ ]:




