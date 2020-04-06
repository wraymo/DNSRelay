use std::thread;
use std::sync::mpsc;
use std::sync::{Arc,Mutex};

enum Message {
    NewJob(Job),
    Terminate,
}

trait FnBox {
    fn call_box(self:Box<Self>);
}

impl<F:FnOnce()> FnBox for F { // 为任意一个FnOnce()trait对象实现 FnBox trait
fn call_box(self: Box<F>) {
    (*self)()
}
}

type Job = Box<dyn FnBox+Send+'static>; // Job 是一个可执行闭包的堆对象

struct Worker {
    id:usize,
    thread:Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id:usize,receiver:Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || {
            loop {
                let message = receiver.lock().unwrap().recv().unwrap();

                match message {
                    Message::NewJob(job) => {
//                        println!("Worker {} 开始执行.",id );
                        job.call_box();
                    },
                    Message::Terminate =>{
                        println!("Worker {} 被告知终止.",id);
                        break;
                    }
                }
            }
        });

        Worker 	{
            id,
            thread:Some(thread),
        }
    }
}


pub struct ThreadPool{
    workers:Vec<Worker>,
    sender:mpsc::Sender<Message>,
}

impl ThreadPool{
    pub fn new(size:usize) -> ThreadPool {
        assert!(size > 0);

        let (sender,receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id,Arc::clone(&receiver)));
        }

        ThreadPool{
            workers,
            sender
        }
    }

    pub fn execute<F>(&self,f:F)
        where F:FnOnce()+Send+'static {
        let job = Box::new(f);
        self.sender.send(Message::NewJob(job)).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        println!("向所有worker发送终止信息.");

        for _ in &mut self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }

        println!("正在关闭所有worker.");

        // join所有线程
        for worker in &mut self.workers {
            println!("Shutting down worker {}",worker.id);
            if let Some(thread) = worker.thread.take(){
                thread.join().unwrap();
            }
        }
    }
}