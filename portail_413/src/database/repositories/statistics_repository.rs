use sqlx::PgPool;
use chrono::{DateTime, Utc, Duration, Datelike};
use anyhow::Result;
use tracing::info;

use crate::handlers::statistics_handler::*;

#[derive(Clone)]
pub struct StatisticsRepository {
    pool: PgPool,
}

impl StatisticsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Récupère les statistiques générales du tableau de bord avec calculs en temps réel
    pub async fn get_dashboard_stats(&self) -> Result<DashboardStats> {
        info!("Computing real-time dashboard statistics from database");

        // 1. Visites actives (statut 'inprogress' ou 'approved' avec date d'aujourd'hui)
        let active_visits = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM visits 
             WHERE status IN ('inprogress', 'approved') 
             AND (actual_start IS NOT NULL OR scheduled_start::date = CURRENT_DATE)"
        ).fetch_one(&self.pool).await? as i32;

        // 2. Total des visiteurs uniques
        let total_visitors = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT id) FROM visitors WHERE created_at <= NOW()"
        ).fetch_one(&self.pool).await? as i32;

        // 3. Visites créées aujourd'hui
        let today_visits = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM visits WHERE DATE(created_at) = CURRENT_DATE"
        ).fetch_one(&self.pool).await? as i32;

        // 4. Approbations en attente
        let pending_approvals = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM visits WHERE status = 'pending'"
        ).fetch_one(&self.pool).await? as i32;

        // Mise à jour optionnelle de la table statistics pour historique
        let _ = self.update_statistics_table(
            active_visits as i64, 
            total_visitors as i64, 
            today_visits as i64, 
            pending_approvals as i64
        ).await;

        let stats = DashboardStats {
            active_visits,
            total_visitors,
            today_visits,
            pending_approvals,
        };

        info!("Dashboard stats computed: active={}, total_visitors={}, today={}, pending={}", 
              active_visits, total_visitors, today_visits, pending_approvals);

        Ok(stats)
    }

    /// Récupère les statistiques détaillées des visites avec calculs mathématiquement exacts
    pub async fn get_visit_statistics(&self, period: &str) -> Result<VisitStatistics> {
        info!("Computing precise visit statistics for period: {}", period);

        let (start_date, end_date) = self.get_period_dates(period);

        // 1. Statistiques de base avec les vrais statuts de la base
        let base_stats = sqlx::query!(
            "SELECT 
                COUNT(*) as total_visits,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_visits,
                COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_visits,
                COUNT(CASE WHEN status = 'inprogress' THEN 1 END) as inprogress_visits,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_visits,
                COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_visits,
                COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_visits
            FROM visits 
            WHERE created_at >= $1 AND created_at <= $2",
            start_date, end_date
        ).fetch_one(&self.pool).await?;

        let total_visits = base_stats.total_visits.unwrap_or(0);
        let completed_visits = base_stats.completed_visits.unwrap_or(0);
        let cancelled_visits = base_stats.cancelled_visits.unwrap_or(0);

        // 2. Durée moyenne précise (en minutes)
        let avg_duration = sqlx::query_scalar::<_, Option<f64>>(
            "SELECT AVG(EXTRACT(EPOCH FROM (actual_end - actual_start))/60.0)
             FROM visits 
             WHERE actual_start IS NOT NULL AND actual_end IS NOT NULL 
             AND created_at >= $1 AND created_at <= $2"
        ).bind(start_date).bind(end_date).fetch_one(&self.pool).await?;

        let average_duration_minutes = avg_duration.unwrap_or(0.0).round() as i32;

        // 3. Calculer les pourcentages pour les statistiques par statut
        let total_f = if total_visits > 0 { total_visits as f64 } else { 1.0 };
        let visits_by_status = vec![
            StatusCount { 
                status: "completed".to_string(), 
                count: completed_visits, 
                percentage: ((completed_visits as f64 / total_f) * 100.0).round() as i32
            },
            StatusCount { 
                status: "cancelled".to_string(), 
                count: cancelled_visits,
                percentage: ((cancelled_visits as f64 / total_f) * 100.0).round() as i32
            },
            StatusCount { 
                status: "inprogress".to_string(), 
                count: base_stats.inprogress_visits.unwrap_or(0),
                percentage: ((base_stats.inprogress_visits.unwrap_or(0) as f64 / total_f) * 100.0).round() as i32
            },
            StatusCount { 
                status: "pending".to_string(), 
                count: base_stats.pending_visits.unwrap_or(0),
                percentage: ((base_stats.pending_visits.unwrap_or(0) as f64 / total_f) * 100.0).round() as i32
            },
            StatusCount { 
                status: "approved".to_string(), 
                count: base_stats.approved_visits.unwrap_or(0),
                percentage: ((base_stats.approved_visits.unwrap_or(0) as f64 / total_f) * 100.0).round() as i32
            },
            StatusCount { 
                status: "rejected".to_string(), 
                count: base_stats.rejected_visits.unwrap_or(0),
                percentage: ((base_stats.rejected_visits.unwrap_or(0) as f64 / total_f) * 100.0).round() as i32
            },
        ];

        // 4. Visites par jour de la semaine
        let visits_by_day = self.get_visits_by_day_precise(start_date, end_date).await?;

        // 5. Visites par heure
        let visits_by_hour = self.get_visits_by_hour_precise(start_date, end_date).await?;

        // 6. Top départements/services (utiliser la bonne colonne 'department')
        let top_departments = self.get_top_departments_precise(start_date, end_date).await?;

        // 7. Heures de pointe
        let peak_hours = self.calculate_peak_hours(&visits_by_hour);

        let statistics = VisitStatistics {
            total_visits,
            completed_visits,
            cancelled_visits,
            average_duration_minutes,
            visits_by_status,
            visits_by_day,
            visits_by_hour,
            top_departments,
            peak_hours,
        };

        info!("Visit statistics computed: total={}, completed={}, cancelled={}, avg_duration={}", 
              total_visits, completed_visits, cancelled_visits, average_duration_minutes);

        Ok(statistics)
    }

    /// Statistiques des visiteurs avec calculs exacts
    pub async fn get_visitor_statistics(&self) -> Result<VisitorStatistics> {
        info!("Computing precise visitor statistics");

        // 1. Visiteurs uniques totaux
        let total_unique_visitors = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT id) FROM visitors"
        ).fetch_one(&self.pool).await?;

        // 2. Nouveaux visiteurs ce mois
        let new_visitors_this_month = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT id) FROM visitors 
             WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE)"
        ).fetch_one(&self.pool).await?;

        // 3. Visiteurs récurrents
        let returning_visitors = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT visitor_id) FROM (
                SELECT visitor_id FROM visits GROUP BY visitor_id HAVING COUNT(*) > 1
             ) as recurring"
        ).fetch_one(&self.pool).await?;

        // 4. Moyenne de visites par visiteur
        let avg_visits_per_visitor = if total_unique_visitors > 0 {
            let total_visits = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM visits"
            ).fetch_one(&self.pool).await?;
            total_visits as f64 / total_unique_visitors as f64
        } else {
            0.0
        };

        // 5. Top organisations (utiliser 'organization' au lieu de 'company')
        let top_companies = self.get_top_organizations_precise().await?;

        // 6. Pays d'origine (mock data pour l'instant)
        let visitor_origin_countries = self.get_visitor_countries_precise().await?;

        let statistics = VisitorStatistics {
            total_unique_visitors,
            new_visitors_this_month,
            returning_visitors,
            average_visits_per_visitor: (avg_visits_per_visitor * 100.0).round() / 100.0,
            top_companies,
            visitor_origin_countries,
        };

        info!("Visitor statistics computed: total={}, new_month={}, returning={}, avg={:.2}", 
              total_unique_visitors, new_visitors_this_month, returning_visitors, avg_visits_per_visitor);

        Ok(statistics)
    }

    /// Données pour graphiques d'activité
    pub async fn get_activity_chart_data(&self) -> Result<ActivityChartData> {
        info!("Computing activity chart data");

        let hourly_visits = self.get_hourly_chart_data().await?;
        let daily_visits = self.get_daily_chart_data().await?;
        let weekly_visits = self.get_weekly_chart_data().await?;
        let monthly_visits = self.get_monthly_chart_data().await?;

        Ok(ActivityChartData {
            hourly_visits,
            daily_visits,
            weekly_visits,
            monthly_visits,
        })
    }

    /// Statistiques d'export corrigées
    pub async fn get_export_statistics(&self) -> Result<ExportStatistics> {
        info!("Computing export statistics");

        let total_exports_this_month = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_logs 
             WHERE action = 'data_export' 
             AND DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE)"
        ).fetch_one(&self.pool).await?;

        // Mock data pour les autres champs
        let exports_by_type = vec![
            ExportTypeCount { export_type: "PDF".to_string(), count: (total_exports_this_month / 2) as i32 },
            ExportTypeCount { export_type: "CSV".to_string(), count: (total_exports_this_month / 3) as i32 },
            ExportTypeCount { export_type: "Excel".to_string(), count: (total_exports_this_month / 4) as i32 },
        ];

        Ok(ExportStatistics {
            total_exports_this_month: total_exports_this_month as i32,
            total_data_exported_mb: (total_exports_this_month * 2) as f64, // Approximation
            most_exported_format: "PDF".to_string(),
            exports_by_type,
            last_export_date: if total_exports_this_month > 0 { 
                Some(Utc::now()) 
            } else { 
                None 
            },
        })
    }

    /// Méthodes individuelles pour les endpoints spécifiques
    pub async fn get_active_visits_count(&self) -> Result<i32> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM visits 
             WHERE status IN ('inprogress', 'approved') 
             AND (actual_start IS NOT NULL OR scheduled_start::date = CURRENT_DATE)"
        ).fetch_one(&self.pool).await? as i32;
        Ok(count)
    }

    pub async fn get_today_visits_count(&self) -> Result<i32> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM visits WHERE DATE(created_at) = CURRENT_DATE"
        ).fetch_one(&self.pool).await? as i32;
        Ok(count)
    }

    pub async fn get_pending_approvals_count(&self) -> Result<i32> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM visits WHERE status = 'pending'"
        ).fetch_one(&self.pool).await? as i32;
        Ok(count)
    }

    pub async fn get_total_visitors_count(&self) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT id) FROM visitors WHERE created_at <= NOW()"
        ).fetch_one(&self.pool).await?;
        Ok(count)
    }

    // ===== MÉTHODES UTILITAIRES PRIVÉES =====

    /// Met à jour la table statistics
    async fn update_statistics_table(&self, active_visits: i64, total_visitors: i64, today_visits: i64, pending_approvals: i64) -> Result<()> {
        // Calcul des hash d'intégrité
        let hash1 = format!("{:x}", md5::compute(format!("active_visits_now_{active_visits}")));
        let hash2 = format!("{:x}", md5::compute(format!("total_visitors_{total_visitors}")));  
        let hash3 = format!("{:x}", md5::compute(format!("total_visits_today_{today_visits}")));
        let hash4 = format!("{:x}", md5::compute(format!("pending_approvals_{pending_approvals}")));
        
        sqlx::query!(
            "INSERT INTO statistics (
                id, metric_name, metric_type, category, value_int, 
                reference_date, description, unit, tags, created_at, updated_at, integrity_hash
            ) VALUES 
            (gen_random_uuid(), 'active_visits_now', 'real_time', 'visits', $1, CURRENT_DATE, 'Visites actuellement en cours', 'count', '{\"visits\",\"real_time\",\"dashboard\"}', NOW(), NOW(), $5),
            (gen_random_uuid(), 'total_visitors', 'cumulative', 'visitors', $2, CURRENT_DATE, 'Total des visiteurs uniques', 'count', '{\"visitors\",\"total\",\"dashboard\"}', NOW(), NOW(), $6),
            (gen_random_uuid(), 'total_visits_today', 'daily', 'visits', $3, CURRENT_DATE, 'Visites créées aujourd''hui', 'count', '{\"visits\",\"daily\",\"dashboard\"}', NOW(), NOW(), $7),
            (gen_random_uuid(), 'pending_approvals', 'real_time', 'visits', $4, CURRENT_DATE, 'Demandes d''approbation en attente', 'count', '{\"visits\",\"pending\",\"dashboard\"}', NOW(), NOW(), $8)
            ON CONFLICT (metric_name, reference_date) 
            DO UPDATE SET 
                value_int = EXCLUDED.value_int,
                updated_at = NOW(),
                integrity_hash = EXCLUDED.integrity_hash",
            active_visits, total_visitors, today_visits, pending_approvals,
            hash1, hash2, hash3, hash4
        ).execute(&self.pool).await.map_err(|e| {
            tracing::error!("Failed to store dashboard statistics: {}", e);
            crate::errors::AppError::Database(e)
        })?;
        
        Ok(())
    }

    /// Calcule les dates de début et fin pour une période donnée
    fn get_period_dates(&self, period: &str) -> (DateTime<Utc>, DateTime<Utc>) {
        let now = Utc::now();
        match period {
            "today" => (
                now.date_naive().and_hms_opt(0, 0, 0).expect("Checked operation").and_utc(),
                now
            ),
            "week" => (
                now - Duration::days(7),
                now
            ),
            "month" => (
                now - Duration::days(30),
                now
            ),
            "year" => (
                now - Duration::days(365),
                now
            ),
            _ => (
                now - Duration::days(7), // défaut: une semaine
                now
            )
        }
    }

    /// Visites par jour de la semaine avec calculs précis
    async fn get_visits_by_day_precise(&self, start_date: DateTime<Utc>, end_date: DateTime<Utc>) -> Result<Vec<DayCount>> {
        let rows = sqlx::query!(
            "SELECT 
                TO_CHAR(created_at, 'Day') as day_name,
                EXTRACT(DOW FROM created_at) as day_number,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= $1 AND created_at <= $2
            GROUP BY TO_CHAR(created_at, 'Day'), EXTRACT(DOW FROM created_at)
            ORDER BY EXTRACT(DOW FROM created_at)",
            start_date, end_date
        ).fetch_all(&self.pool).await?;

        let mut day_counts = Vec::new();
        for row in rows {
            day_counts.push(DayCount {
                day: row.day_name.unwrap_or_default().trim().to_string(),
                count: row.count.unwrap_or(0),
            });
        }

        Ok(day_counts)
    }

    /// Visites par heure avec distribution 24h
    async fn get_visits_by_hour_precise(&self, start_date: DateTime<Utc>, end_date: DateTime<Utc>) -> Result<Vec<HourCount>> {
        let rows = sqlx::query!(
            "SELECT 
                EXTRACT(HOUR FROM created_at) as hour,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= $1 AND created_at <= $2
            GROUP BY EXTRACT(HOUR FROM created_at)
            ORDER BY EXTRACT(HOUR FROM created_at)",
            start_date, end_date
        ).fetch_all(&self.pool).await?;

        let mut hour_counts = Vec::new();
        for row in rows {
            let hour = row.hour.unwrap_or(sqlx::types::BigDecimal::from(0)).to_string().parse::<i32>().unwrap_or(0);
            hour_counts.push(HourCount {
                hour,
                count: row.count.unwrap_or(0),
            });
        }

        // Remplir les heures manquantes avec 0
        for h in 0..24 {
            if !hour_counts.iter().any(|hc| hc.hour == h) {
                hour_counts.push(HourCount { hour: h, count: 0 });
            }
        }
        hour_counts.sort_by_key(|hc| hc.hour);

        Ok(hour_counts)
    }

    /// Top départements avec calculs exacts (utiliser la bonne colonne)
    async fn get_top_departments_precise(&self, start_date: DateTime<Utc>, end_date: DateTime<Utc>) -> Result<Vec<DepartmentCount>> {
        let rows = sqlx::query!(
            "SELECT 
                COALESCE(department, 'Non spécifié') as department,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= $1 AND created_at <= $2
            GROUP BY COALESCE(department, 'Non spécifié')
            ORDER BY COUNT(*) DESC
            LIMIT 10",
            start_date, end_date
        ).fetch_all(&self.pool).await?;

        let mut departments = Vec::new();
        for row in rows {
            departments.push(DepartmentCount {
                department: row.department.unwrap_or_default(),
                count: row.count.unwrap_or(0),
            });
        }

        Ok(departments)
    }

    /// Top organisations avec calculs exacts
    async fn get_top_organizations_precise(&self) -> Result<Vec<CompanyCount>> {
        let rows = sqlx::query!(
            "SELECT 
                COALESCE(organization, 'Non spécifiée') as organization,
                COUNT(DISTINCT v.id) as visitor_count
            FROM visitors v
            GROUP BY COALESCE(organization, 'Non spécifiée')
            ORDER BY COUNT(DISTINCT v.id) DESC
            LIMIT 10"
        ).fetch_all(&self.pool).await?;

        let mut companies = Vec::new();
        for row in rows {
            companies.push(CompanyCount {
                company: row.organization.unwrap_or_default(),
                visitor_count: row.visitor_count.unwrap_or(0),
            });
        }

        Ok(companies)
    }

    /// Pays d'origine des visiteurs (données mockées)
    async fn get_visitor_countries_precise(&self) -> Result<Vec<CountryCount>> {
        Ok(vec![
            CountryCount { country: "France".to_string(), count: 150 },
            CountryCount { country: "Belgique".to_string(), count: 25 },
            CountryCount { country: "Allemagne".to_string(), count: 20 },
            CountryCount { country: "Espagne".to_string(), count: 15 },
            CountryCount { country: "Italie".to_string(), count: 10 },
        ])
    }

    /// Calcule les heures de pointe mathématiquement
    fn calculate_peak_hours(&self, visits_by_hour: &[HourCount]) -> Vec<String> {
        if visits_by_hour.is_empty() {
            return vec![];
        }

        let max_count = visits_by_hour.iter().map(|h| h.count).max().unwrap_or(0);
        let threshold = (max_count as f64 * 0.8) as i64;
        
        visits_by_hour
            .iter()
            .filter(|h| h.count >= threshold)
            .map(|h| format!("{}h-{}h", h.hour, h.hour + 1))
            .collect()
    }

    // Méthodes pour les graphiques
    async fn get_hourly_chart_data(&self) -> Result<Vec<ChartPoint>> {
        let rows = sqlx::query!(
            "SELECT 
                EXTRACT(HOUR FROM created_at) as hour,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= NOW() - INTERVAL '24 hours'
            GROUP BY EXTRACT(HOUR FROM created_at)
            ORDER BY EXTRACT(HOUR FROM created_at)"
        ).fetch_all(&self.pool).await?;

        let mut chart_data = Vec::new();
        for row in rows {
            let hour = row.hour.unwrap_or(sqlx::types::BigDecimal::from(0)).to_string().parse::<i32>().unwrap_or(0);
            chart_data.push(ChartPoint {
                label: format!("{hour}h"),
                value: row.count.unwrap_or(0) as f64,
            });
        }

        Ok(chart_data)
    }

    async fn get_daily_chart_data(&self) -> Result<Vec<ChartPoint>> {
        let rows = sqlx::query!(
            "SELECT 
                DATE(created_at) as day,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= NOW() - INTERVAL '7 days'
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at)"
        ).fetch_all(&self.pool).await?;

        let mut chart_data = Vec::new();
        for row in rows {
            if let Some(day) = row.day {
                chart_data.push(ChartPoint {
                    label: day.format("%d/%m").to_string(),
                    value: row.count.unwrap_or(0) as f64,
                });
            }
        }

        Ok(chart_data)
    }

    async fn get_weekly_chart_data(&self) -> Result<Vec<ChartPoint>> {
        let rows = sqlx::query!(
            "SELECT 
                DATE_TRUNC('week', created_at) as week,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= NOW() - INTERVAL '12 weeks'
            GROUP BY DATE_TRUNC('week', created_at)
            ORDER BY DATE_TRUNC('week', created_at)"
        ).fetch_all(&self.pool).await?;

        let mut chart_data = Vec::new();
        for row in rows {
            if let Some(week) = row.week {
                chart_data.push(ChartPoint {
                    label: format!("S{}", week.iso_week().week()),
                    value: row.count.unwrap_or(0) as f64,
                });
            }
        }

        Ok(chart_data)
    }

    async fn get_monthly_chart_data(&self) -> Result<Vec<ChartPoint>> {
        let rows = sqlx::query!(
            "SELECT 
                DATE_TRUNC('month', created_at) as month,
                COUNT(*) as count
            FROM visits 
            WHERE created_at >= NOW() - INTERVAL '12 months'
            GROUP BY DATE_TRUNC('month', created_at)
            ORDER BY DATE_TRUNC('month', created_at)"
        ).fetch_all(&self.pool).await?;

        let mut chart_data = Vec::new();
        for row in rows {
            if let Some(month) = row.month {
                chart_data.push(ChartPoint {
                    label: month.format("%m/%Y").to_string(),
                    value: row.count.unwrap_or(0) as f64,
                });
            }
        }

        Ok(chart_data)
    }
}
