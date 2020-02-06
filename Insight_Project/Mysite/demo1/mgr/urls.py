from django.urls import path
from mgr import sign_in_out
# from mgr import customer, medicine, order

urlpatterns = [
    path('signin/', sign_in_out.signin),
    path('signout/', sign_in_out.signout),
    # path('customers', customer.dispatcher),
    # path('medicines', medicine.dispatcher),
    # path('orders', order.dispatcher),
]