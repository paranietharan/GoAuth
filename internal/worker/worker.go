package worker

import (
	"GoAuth/internal/email"
	"context"
	"log"
)

type EmailJob struct {
	To      string
	Subject string
	Body    string
}

type JobQueue struct {
	jobs chan *EmailJob
}

func NewJobQueue(capacity int) *JobQueue {
	return &JobQueue{
		jobs: make(chan *EmailJob, capacity),
	}
}

func (q *JobQueue) Push(job *EmailJob) {
	q.jobs <- job
}

func (q *JobQueue) Pop() *EmailJob {
	return <-q.jobs
}

type EmailWorker struct {
	emailService          *email.Service
	jobQueue              *JobQueue
	isLocalDevWithoutSmtp bool
}

func NewEmailWorker(emailService *email.Service, jobQueue *JobQueue, isLocalDevWithoutSmtp bool) *EmailWorker {
	return &EmailWorker{
		emailService:          emailService,
		jobQueue:              jobQueue,
		isLocalDevWithoutSmtp: isLocalDevWithoutSmtp,
	}
}

func (w *EmailWorker) Start(ctx context.Context, numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		go w.worker(ctx, i)
	}
	log.Printf("Started %d email workers", numWorkers)
}

func (w *EmailWorker) worker(ctx context.Context, id int) {
	log.Printf("Email worker %d started", id)
	for {
		select {
		case <-ctx.Done():
			log.Printf("Email worker %d stopped", id)
			return
		case job := <-w.jobQueue.jobs:
			w.processJob(job, id)
		}
	}
}

func (w *EmailWorker) processJob(job *EmailJob, workerID int) {
	log.Printf("Worker %d: Sending email to %s", workerID, job.To)

	if w.isLocalDevWithoutSmtp {
		log.Printf("Worker %d: [DEV MODE] Email to %s: Subject: %s, Body: %s", workerID, job.To, job.Subject, job.Body)
		return
	}

	if err := w.emailService.SendEmail(job.To, job.Subject, job.Body); err != nil {
		log.Printf("Worker %d: Failed to send email to %s: %v", workerID, job.To, err)
		return
	}

	log.Printf("Worker %d: Successfully sent email to %s", workerID, job.To)
}
