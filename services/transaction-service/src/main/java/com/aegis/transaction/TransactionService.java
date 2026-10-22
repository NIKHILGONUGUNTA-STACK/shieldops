package com.aegis.transaction;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

@Service
public class TransactionService {
    private final BeneficiaryRepository beneficiaries;
    private final TransactionRepository transactions;
    private final AccountClient accounts;

    public TransactionService(BeneficiaryRepository beneficiaries,
                              TransactionRepository transactions,
                              AccountClient accounts) {
        this.beneficiaries = beneficiaries;
        this.transactions = transactions;
        this.accounts = accounts;
    }

    public List<TransactionController.BeneficiaryView> listBeneficiaries(UUID customerId) {
        var list = customerId == null ? beneficiaries.findAll() : beneficiaries.findByCustomerId(customerId);
        return list.stream().map(TransactionController.BeneficiaryView::from).toList();
    }

    public TransactionController.BeneficiaryView createBeneficiary(TransactionController.CreateBeneficiary request) {
        Beneficiary saved = beneficiaries.save(new Beneficiary(
                request.customerId(),
                request.name(),
                request.destinationAccountReference(),
                request.currency()
        ));
        return TransactionController.BeneficiaryView.from(saved);
    }

    public TransactionController.BeneficiaryView getBeneficiaryView(UUID id) {
        return TransactionController.BeneficiaryView.from(getBeneficiary(id));
    }

    @Transactional
    public TransactionController.BeneficiaryView verifyBeneficiary(UUID id) {
        Beneficiary b = getBeneficiary(id);
        try {
            b.verify();
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
        return TransactionController.BeneficiaryView.from(b);
    }

    public List<TransactionController.TransactionView> listTransactions(UUID customerId) {
        var list = customerId == null ? transactions.findAll() : transactions.findByCustomerId(customerId);
        return list.stream().map(TransactionController.TransactionView::from).toList();
    }

    public TransactionController.TransactionView getTransaction(UUID id) {
        return TransactionController.TransactionView.from(
                transactions.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Transaction not found"))
        );
    }

    public TransactionController.TransactionView transfer(TransactionController.TransferRequest request, String key) {
        String reference = (key == null || key.isBlank()) ? request.reference() : key;
        if (reference == null || reference.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency-Key or reference is required");
        }
        var prior = transactions.findByReference(reference);
        TransactionRecord transfer;
        if (prior.isPresent()) {
            TransactionRecord existing = prior.get();
            if (!existing.getCustomerId().equals(request.customerId())
                    || !existing.getSourceAccountId().equals(request.sourceAccountId())
                    || !existing.getBeneficiaryId().equals(request.beneficiaryId())
                    || existing.getAmount().compareTo(request.amount()) != 0
                    || !existing.getCurrency().equals(request.currency())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency key was already used for a different transfer");
            }
            if ("COMPLETED".equals(existing.getStatus())) {
                return TransactionController.TransactionView.from(existing);
            }
            if (!"PENDING".equals(existing.getStatus()) && !"AUTHORIZED".equals(existing.getStatus())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Transfer is not retryable in its current state");
            }
            transfer = existing;
        } else {
            Beneficiary beneficiary = getBeneficiary(request.beneficiaryId());
            if (!beneficiary.getCustomerId().equals(request.customerId())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Beneficiary does not belong to customer");
            }
            if (!"VERIFIED".equals(beneficiary.getStatus())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Beneficiary must be verified");
            }
            AccountClient.AccountSummary source;
            try {
                source = accounts.get(request.sourceAccountId());
            } catch (org.springframework.web.client.RestClientException e) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Account service unavailable");
            }
            if (!source.customerId().equals(request.customerId())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Source account does not belong to customer");
            }
            if (!"ACTIVE".equals(source.status())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Source account is not active");
            }
            if (!source.currency().equals(request.currency()) || !beneficiary.getCurrency().equals(request.currency())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Currency mismatch");
            }
            if (source.balance().compareTo(request.amount()) < 0) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Insufficient available balance");
            }
            transfer = transactions.save(new TransactionRecord(reference, request.customerId(), request.sourceAccountId(), request.beneficiaryId(), request.amount(), request.currency()));
            transfer.transition("PENDING");
            transfer = transactions.save(transfer);
        }

        if ("AUTHORIZED".equals(transfer.getStatus())) {
            transfer.transition("COMPLETED");
            return TransactionController.TransactionView.from(transactions.save(transfer));
        }

        try {
            accounts.debit(request.sourceAccountId(), reference, request.amount(), request.currency());
            transfer.transition("AUTHORIZED");
            transactions.save(transfer);
            transfer.transition("COMPLETED");
            return TransactionController.TransactionView.from(transactions.save(transfer));
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            transfer.transition("FAILED");
            transactions.save(transfer);
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Account rejected transfer debit");
        } catch (org.springframework.web.client.RestClientException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Account service unavailable; transfer can be retried safely");
        }
    }

    private Beneficiary getBeneficiary(UUID id) {
        return beneficiaries.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Beneficiary not found"));
    }
}
