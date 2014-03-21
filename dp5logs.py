import time

LOG_FILE = file("logs/Log.log" , "a")

class logger:
   def __init__(self, name):
      self.name = name
      self.basetime = time.clock()
      self.events = []
      self.f = LOG_FILE
      self.last = None

   def log(self, event, aID):
      now = time.clock()
      
      self.events += ["%s -- %s -- [%s] %s\n" % (now, self.name,  aID, ", ".join(event))]
      if len(self.events) > 10:
        self.flush()
      
      if self.last == None:
        self.last = now

      if (now - self.last) > 5.0:
        self.last = now
        self.flush()

        
   def flush(self):
      self.f.write("".join(self.events))
      self.events = []
      self.f.flush()

   def __del__(self):
      # self.f.close()
      pass
         
        
