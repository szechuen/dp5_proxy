import time

LOG_FILE = {}

class logger:
   def __init__(self, name, ltype):
      self.name = name
      self.basetime = time.time()

      fname = "logs/Log-%s.log" % ltype
      if fname not in LOG_FILE:
        LOG_FILE[fname] = file(fname, "w")
       
      self.events = []
      self.f = LOG_FILE[fname]
      self.last = None

   def log(self, event, aID):
      now = time.time() - self.basetime
      log_line = "%s -- %s -- [%s] %s\n" % (now, self.name,  aID, ", ".join(event))

      self.events += [log_line]
      self.flush()
      
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
         
        
