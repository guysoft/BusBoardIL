BusBoardIL
==========

A dashboard that given GPS coordinates shows the upcomming busses in Israel, requires access to an instance of `curlbus <https://github.com/elad661/curlbus>`_.


How to use it?
--------------

`Running demo here <https://busboardil.gnethomelinux.com>`_ 

Features
--------

* Given GPS coordinates shows upcomming busses in a radius.

Developing
----------

Requirements
~~~~~~~~~~~~

#. Python 3
#. mariadb

Install
~~~~~~~

Run the following::

    sudo apt-get install python3-pip
    git clone https://github.com/guysoft/BusBoardIL.git
    cd BusBoardIL
    sudo pip3 install -r requirements.txt
    cd src
    cp config.ini.example config.ini
    
Edit config.ini to include access to a mariadb instance db.

4. Message ``/start`` to your bot to start.

Install using docker
~~~~~~~~~~~~~~~~~~~~
    
* TODO


Code contributions are loved!
